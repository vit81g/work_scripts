#requires -Version 5.1
<##
.SYNOPSIS
  Read-only Windows Server access and privilege inventory for one AD domain.
.DESCRIPTION
  Queries enabled AD computer objects whose OperatingSystem contains 'Server'.
  Uses WinRM to inspect local Administrators / Remote Desktop Users and the
  resultant user-rights assignments (secedit /export /mergedpolicy).
  Expands domain AD groups with explicit membership paths and emits four CSVs.
  Does not inspect historic sessions or change access policy.
.NOTES
  Run from 64-bit Windows PowerShell 5.1 with RSAT ActiveDirectory.
  Must be permitted to query local groups and export effective local security policy.
  Test on a restricted set first using -MaxServers 3.
#>
[CmdletBinding()]
param(
  [string]$Domain,
  [string]$OutputDirectory = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'ServerAccessAudit'),
  [ValidateRange(1,100000)][int]$MaxServers = 100000,
  [ValidateRange(1,64)][int]$ThrottleLimit = 12,
  [ValidateRange(5,120)][int]$OpenTimeoutSeconds = 15,
  [ValidateRange(1,100)][int]$MaxGroupDepth = 15,
  [ValidateRange(1,100000)][int]$MaxMembersPerRoot = 10000
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1.' }
Import-Module ActiveDirectory -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($Domain)) {
  $Domain = Read-Host 'DNS name of the AD domain to audit (e.g. example.test)'
}
$Domain = $Domain.Trim()
if ($Domain -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*$') { throw 'Invalid domain name.' }
$Credential = Get-Credential -Message "Account permitted to query AD and remotely inspect servers in $Domain"
if ($null -eq $Credential) { throw 'Credentials were not provided.' }
$adParams = @{ Server=$Domain; Credential=$Credential; ErrorAction='Stop' }
$adDomain = Get-ADDomain -Identity $Domain @adParams
$dnsDomain = [string]$adDomain.DNSRoot
$netbiosDomain = [string]$adDomain.NetBIOSName
$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Join-Path $OutputDirectory ("{0}_{1}" -f $dnsDomain,$runStamp)
try {
  New-Item -ItemType Directory -Path $runDir -Force -ErrorAction Stop | Out-Null
} catch {
  throw "Cannot create output directory '$runDir'. Set -OutputDirectory to a writable path. Details: $($_.Exception.Message)"
}

$errors = [System.Collections.Generic.List[object]]::new()
function Add-Issue {
  param([string]$Computer,[string]$Stage,[string]$Message)
  $script:errors.Add([pscustomobject]@{ ComputerName=$Computer; Stage=$Stage; Message=$Message })
}
Write-Host "Querying AD domain $dnsDomain ..." -ForegroundColor Cyan
$adComputers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem,DNSHostName @adParams |
  Where-Object { $_.OperatingSystem -like '*Server*' } |
  Sort-Object Name | Select-Object -First $MaxServers)
if ($adComputers.Count -eq 0) { throw 'No enabled Server OS objects found in the selected domain.' }
Write-Host "Servers selected: $($adComputers.Count). Parallel WinRM limit: $ThrottleLimit" -ForegroundColor Cyan

# Remote worker returns a single result object and never modifies security settings.
$worker = {
  param([string]$Server, [pscredential]$Cred, [int]$TimeoutMs)
  $out = [pscustomobject]@{
    ComputerName=$Server; Status='Error'; ErrorMessage=''; Members=@(); Rights=@(); RdpEnabled=$null
  }
  $s = $null
  try {
    $opts = New-PSSessionOption -OpenTimeout $TimeoutMs -OperationTimeout 60000
    $s = New-PSSession -ComputerName $Server -Credential $Cred -SessionOption $opts -ErrorAction Stop
    $data = Invoke-Command -Session $s -ErrorAction Stop -ScriptBlock {
      $issues = [System.Collections.Generic.List[string]]::new()
      $members = [System.Collections.Generic.List[object]]::new()
      $rights = [System.Collections.Generic.List[object]]::new()
      foreach ($entry in @(
        @{Label='Administrators'; Sid='S-1-5-32-544'},
        @{Label='Remote Desktop Users'; Sid='S-1-5-32-555'}
      )) {
        try {
          $g = Get-LocalGroup -SID ([System.Security.Principal.SecurityIdentifier]::new($entry.Sid)) -ErrorAction Stop
          $localMembers = @(Get-LocalGroupMember -Group $g -ErrorAction Stop)
          foreach ($m in $localMembers) {
            $id = if ($m.SID) { $m.SID.Value } else { '' }
            $members.Add([pscustomobject]@{
              LocalGroup=$entry.Label; LocalGroupSID=$entry.Sid
              MemberName=[string]$m.Name; MemberSID=[string]$id
              ObjectClass=[string]$m.ObjectClass; PrincipalSource=[string]$m.PrincipalSource
            })
          }
        } catch { $issues.Add("LocalGroup/$($entry.Label): $($_.Exception.Message)") }
      }
      $cfg = Join-Path $env:TEMP ("server_access_{0}.inf" -f [guid]::NewGuid().ToString('N'))
      $log = [IO.Path]::ChangeExtension($cfg,'.log')
      try {
        $p = Start-Process -FilePath "$env:windir\System32\secedit.exe" -ArgumentList @(
          '/export','/mergedpolicy','/areas','USER_RIGHTS','/cfg',('"'+$cfg+'"'),'/log',('"'+$log+'"'),'/quiet'
        ) -Wait -PassThru -NoNewWindow -ErrorAction Stop
        if ($p.ExitCode -ne 0) { throw "secedit exit code $($p.ExitCode)" }
        if (-not (Test-Path -LiteralPath $cfg)) { throw 'secedit did not create the INF file' }
        # secedit writes UTF-16LE INF on supported Windows Server versions.
        foreach ($line in (Get-Content -LiteralPath $cfg -Encoding Unicode -ErrorAction Stop)) {
          if ($line -match '^\s*(Se[A-Za-z0-9]+)\s*=\s*(.*)$') {
            $rightName = $Matches[1]
            foreach ($subject in ($Matches[2] -split ',')) {
              $value = $subject.Trim().TrimStart('*')
              if ($value) { $rights.Add([pscustomobject]@{ Right=$rightName; Principal=$value }) }
            }
          }
        }
      } catch { $issues.Add("UserRights: $($_.Exception.Message)") }
      finally {
        Remove-Item -LiteralPath $cfg,$log -Force -ErrorAction SilentlyContinue
      }
      $rdp = $null
      try {
        $v = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
        $rdp = ($v.fDenyTSConnections -eq 0)
      } catch { $issues.Add("RDPConfiguration: $($_.Exception.Message)") }
      [pscustomobject]@{ Members=@($members.ToArray()); Rights=@($rights.ToArray());
        RdpEnabled=$rdp; Issues=@($issues.ToArray()) }
    }
    $out.Members = @($data.Members)
    $out.Rights = @($data.Rights)
    $out.RdpEnabled = $data.RdpEnabled
    $out.Status = if (@($data.Issues).Count) { 'Partial' } else { 'Success' }
    $out.ErrorMessage = @($data.Issues) -join ' | '
  } catch {
    $out.Status='Error'
    $out.ErrorMessage=$_.Exception.Message
  } finally { if ($null -ne $s) { Remove-PSSession -Session $s -ErrorAction SilentlyContinue } }
  return $out
}

# A bounded runspace pool, unlike launching one unbounded job per machine.
$pool = [runspacefactory]::CreateRunspacePool(1,$ThrottleLimit)
$pool.Open()
$pending = [System.Collections.Generic.List[object]]::new()
$serverResults = [System.Collections.Generic.List[object]]::new()
try {
  foreach ($c in $adComputers) {
    $target = if ($c.DNSHostName) { [string]$c.DNSHostName } else { [string]$c.Name }
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($worker.ToString()).AddArgument($target).AddArgument($Credential).AddArgument($OpenTimeoutSeconds*1000)
    $handle = $ps.BeginInvoke()
    $pending.Add([pscustomobject]@{ Host=$target; PowerShell=$ps; Handle=$handle })
  }
  while ($pending.Count -gt 0) {
    foreach ($j in @($pending.ToArray())) {
      if (-not $j.Handle.IsCompleted) { continue }
      try {
        foreach ($item in @($j.PowerShell.EndInvoke($j.Handle))) { $serverResults.Add($item) }
        if ($j.PowerShell.HadErrors) {
          foreach ($e in $j.PowerShell.Streams.Error) { Add-Issue $j.Host 'Runspace' ([string]$e) }
        }
      } catch {
        $serverResults.Add([pscustomobject]@{
          ComputerName=$j.Host; Status='Error'; ErrorMessage=$_.Exception.Message;
          Members=@(); Rights=@(); RdpEnabled=$null
        })
      } finally { $j.PowerShell.Dispose(); $null = $pending.Remove($j) }
    }
    if ($pending.Count) { Start-Sleep -Milliseconds 150 }
  }
} finally {
  foreach ($j in $pending) { try { $j.PowerShell.Stop(); $j.PowerShell.Dispose() } catch {} }
  $pool.Close(); $pool.Dispose()
}

# Resolve domain principals, optionally expand AD groups, and retain each membership path.
$groupCache = @{}
$principalCache = @{}
$details = [System.Collections.Generic.List[object]]::new()
$rightsRaw = [System.Collections.Generic.List[object]]::new()
function Resolve-Principal {
  param([string]$Sid,[string]$Fallback)
  if ([string]::IsNullOrWhiteSpace($Sid)) {
    return [pscustomobject]@{ Name=$Fallback; SID=''; Type='Unknown'; DN=''; Enabled='Unknown' }
  }
  if ($principalCache.ContainsKey($Sid)) { return $principalCache[$Sid] }
  $name=$Fallback; $type='Unknown'; $dn=''; $enabled='Unknown'
  $domainSidPrefix = [string]$adDomain.DomainSID.Value
  if ($Sid.StartsWith($domainSidPrefix + '-', [System.StringComparison]::OrdinalIgnoreCase)) {
    $obj=$null
    try { $obj=Get-ADGroup -Identity $Sid -Server $dnsDomain -Credential $Credential -ErrorAction Stop; $type='group' } catch {}
    if ($null -eq $obj) {
      try { $obj=Get-ADUser -Identity $Sid -Server $dnsDomain -Credential $Credential -Properties Enabled -ErrorAction Stop; $type='user' } catch {}
    }
    if ($null -eq $obj) {
      try { $obj=Get-ADComputer -Identity $Sid -Server $dnsDomain -Credential $Credential -Properties Enabled -ErrorAction Stop; $type='computer' } catch {}
    }
    if ($null -ne $obj) {
      $dn=[string]$obj.DistinguishedName
      if ($obj.SamAccountName) { $name="$netbiosDomain\$($obj.SamAccountName)" }
      if ($type -in @('user','computer')) { $enabled=if ($obj.Enabled) {'Yes'} else {'No'} }
    } else {
      Add-Issue '' 'ADResolve' "Cannot resolve current-domain SID $Sid (deleted, inaccessible, or unsupported principal)"
    }
  } elseif ($Sid -match '^S-1-5-21-') {
    # A trusted or local-machine SID must not be falsely labelled as belonging to this AD domain.
    Add-Issue '' 'ADResolve' "Foreign/local SID $Sid is not expanded by the selected-domain resolver"
  }
  $resolved = [pscustomobject]@{ Name=$name; SID=$Sid; Type=$type; DN=$dn; Enabled=$enabled }
  $principalCache[$Sid] = $resolved
  return $resolved
}
function Add-Detail {
  param($HostName,$Grant,$Root,$Identity,$Depth,$Path,$GroupSID,$RdpEnabled)
  $role = switch ($Grant) {
    'Administrators' { 'Administrator' }
    'Remote Desktop Users' { 'RDPGroupMember' }
    { $_ -in @('SeBackupPrivilege','SeRestorePrivilege','SeDebugPrivilege','SeTakeOwnershipPrivilege','SeSecurityPrivilege','SeTcbPrivilege','SeLoadDriverPrivilege','SeImpersonatePrivilege','SeRemoteShutdownPrivilege') } { 'ElevatedRightAssigned' }
    default { 'AssignedUserRight' }
  }
  $details.Add([pscustomobject]@{
    ComputerName=$HostName; Grant=$Grant; PrivilegeLevel=$role
    PrincipalName=[string]$Identity.Name; PrincipalSID=[string]$Identity.SID
    PrincipalType=[string]$Identity.Type; AccountEnabled=[string]$Identity.Enabled
    RootPrincipal=$Root; MembershipPath=$Path; Depth=$Depth
    DirectMember=($Depth -eq 0); LocalGroupSID=$GroupSID
    RdpServiceEnabled=if ($null -eq $RdpEnabled) { 'Unknown' } elseif ($RdpEnabled) { 'Yes' } else { 'No' }
  })
}
function Expand-RootGroup {
  param([string]$HostName,[string]$Grant,[string]$RootName,[string]$RootSid,[string]$GroupSid,$RdpEnabled)
  $root=Resolve-Principal -Sid $RootSid -Fallback $RootName
  Add-Detail $HostName $Grant $RootName $root 0 $RootName $GroupSid $RdpEnabled
  if ($root.Type -ne 'group' -or -not $root.DN) { return }
  $q = [System.Collections.Generic.Queue[object]]::new()
  $q.Enqueue([pscustomobject]@{ DN=$root.DN; Path=$RootName; Depth=0; Visited=@($root.DN) })
  $count=0
  while ($q.Count) {
    $node=$q.Dequeue()
    if ($node.Depth -ge $MaxGroupDepth) {
      Add-Issue $HostName 'ADExpansion' "Depth limit ($MaxGroupDepth) for $RootName at $($node.Path)"; continue
    }
    try {
      if ($groupCache.ContainsKey($node.DN)) { $children=$groupCache[$node.DN] }
      else {
        $children=@(Get-ADGroupMember -Identity $node.DN -Server $dnsDomain -Credential $Credential -ErrorAction Stop)
        $groupCache[$node.DN]=$children
      }
    } catch {
      Add-Issue $HostName 'ADExpansion' "Cannot expand $($node.DN): $($_.Exception.Message)"; continue
    }
    foreach ($child in $children) {
      $count++
      if ($count -gt $MaxMembersPerRoot) {
        Add-Issue $HostName 'ADExpansion' "Member/path limit ($MaxMembersPerRoot) reached for $RootName"
        return
      }
      $childSid=if ($child.SID) { [string]$child.SID.Value } else { '' }
      $childName=if ($child.SamAccountName) { "$netbiosDomain\$($child.SamAccountName)" } else { [string]$child.Name }
      $resolved=Resolve-Principal -Sid $childSid -Fallback $childName
      $chain="$($node.Path) -> $($resolved.Name)"
      Add-Detail $HostName $Grant $RootName $resolved ($node.Depth+1) $chain $GroupSid $RdpEnabled
      if ($child.objectClass -eq 'group' -and $child.DistinguishedName) {
        $childDn=[string]$child.DistinguishedName
        if ($node.Visited -contains $childDn) {
          Add-Issue $HostName 'ADExpansion' "Cycle detected: $chain"
        } else {
          $q.Enqueue([pscustomobject]@{
            DN=$childDn; Path=$chain; Depth=$node.Depth+1; Visited=@($node.Visited)+@($childDn)
          })
        }
      }
    }
  }
}

$importantRights = @(
  'SeRemoteInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight',
  'SeInteractiveLogonRight','SeDenyInteractiveLogonRight',
  'SeBackupPrivilege','SeRestorePrivilege','SeDebugPrivilege',
  'SeTakeOwnershipPrivilege','SeSecurityPrivilege','SeTcbPrivilege',
  'SeLoadDriverPrivilege','SeImpersonatePrivilege',
  'SeRemoteShutdownPrivilege','SeShutdownPrivilege','SeServiceLogonRight',
  'SeBatchLogonRight'
)
foreach ($sr in $serverResults) {
  if ($sr.ErrorMessage) { Add-Issue $sr.ComputerName $sr.Status $sr.ErrorMessage }
  if ($sr.Status -eq 'Error') { continue }
  foreach ($m in @($sr.Members)) {
    Expand-RootGroup -HostName $sr.ComputerName -Grant $m.LocalGroup -RootName $m.MemberName `
      -RootSid $m.MemberSID -GroupSid $m.LocalGroupSID -RdpEnabled $sr.RdpEnabled
  }
  foreach ($r in @($sr.Rights)) {
    if ($r.Right -notin $importantRights) { continue }
    $rawSid=[string]$r.Principal
    $identity=Resolve-Principal -Sid $rawSid -Fallback $rawSid
    $rightsRaw.Add([pscustomobject]@{
      ComputerName=$sr.ComputerName; Right=$r.Right; PrincipalName=$identity.Name;
      PrincipalSID=$rawSid; PrincipalType=$identity.Type; AccountEnabled=$identity.Enabled
    })
    # Built-in local groups in User Rights Assignment must be expanded through
    # the actual membership collected from this server, including nested AD groups.
    if ($rawSid -in @('S-1-5-32-544','S-1-5-32-555')) {
      $localLabel=if ($rawSid -eq 'S-1-5-32-544') {'Administrators'} else {'Remote Desktop Users'}
      foreach ($lm in @($sr.Members | Where-Object { $_.LocalGroup -eq $localLabel })) {
        Expand-RootGroup -HostName $sr.ComputerName -Grant $r.Right -RootName $lm.MemberName `
          -RootSid $lm.MemberSID -GroupSid $rawSid -RdpEnabled $sr.RdpEnabled
      }
    }
    # For AD security groups, expose both the group and its nested users.
    elseif ($identity.Type -eq 'group') {
      Expand-RootGroup -HostName $sr.ComputerName -Grant $r.Right -RootName $identity.Name `
        -RootSid $rawSid -GroupSid '' -RdpEnabled $sr.RdpEnabled
    } else {
      Add-Detail $sr.ComputerName $r.Right $identity.Name $identity 0 $identity.Name '' $sr.RdpEnabled
    }
  }
}

# One row per resolved principal/server. These are configuration-derived signals,
# NOT verified logon capability or a complete Windows token simulation.
$principalSummary=[System.Collections.Generic.List[object]]::new()
$byPrincipal=@($details | Group-Object -Property ComputerName,PrincipalSID)
foreach ($bundle in $byPrincipal) {
  $rows=@($bundle.Group)
  $first=$rows[0]
  if ([string]::IsNullOrWhiteSpace($first.PrincipalSID)) { continue }
  $grants=@($rows | Select-Object -ExpandProperty Grant -Unique)
  $isAdmin=('Administrators' -in $grants)
  $isElevated=@($rows | Where-Object { $_.PrivilegeLevel -eq 'ElevatedRightAssigned' }).Count -gt 0
  $level=if ($isAdmin) {'Administrator'} elseif ($isElevated) {'Elevated'} else {'UserOrOther'}
  $allow=('SeRemoteInteractiveLogonRight' -in $grants)
  $deny=('SeDenyRemoteInteractiveLogonRight' -in $grants)
  $rdpConfigured=if ($first.RdpServiceEnabled -eq 'No') {'DisabledOnServer'} `
    elseif ($deny) {'DenyRightFound'} elseif ($allow) {'AllowRightFound_NotVerified'} `
    else {'NoAllowRightFound_NotVerified'}
  $principalSummary.Add([pscustomobject]@{
    ComputerName=$first.ComputerName; PrincipalName=$first.PrincipalName;
    PrincipalSID=$first.PrincipalSID; PrincipalType=$first.PrincipalType;
    AccountEnabled=$first.AccountEnabled; PrivilegeLevel=$level;
    RdpPolicySignal=$rdpConfigured; GrantedVia=($grants -join ' | ');
    MembershipPaths=(@($rows | Select-Object -ExpandProperty MembershipPath -Unique) -join ' | ')
  })
}

# One row per server; detailed report retains explicit inheritance evidence.
$summary=[System.Collections.Generic.List[object]]::new()
$i=0
foreach ($sr in ($serverResults | Sort-Object ComputerName)) {
  $i++
  $hostRows=@($details | Where-Object { $_.ComputerName -eq $sr.ComputerName })
  $rdpRoots=@($hostRows | Where-Object { $_.Grant -eq 'Remote Desktop Users' -and $_.Depth -eq 0 } |
    Select-Object -ExpandProperty PrincipalName -Unique)
  $adminRoots=@($hostRows | Where-Object { $_.Grant -eq 'Administrators' -and $_.Depth -eq 0 } |
    Select-Object -ExpandProperty PrincipalName -Unique)
  $summary.Add([pscustomobject]@{
    Number=$i; ComputerName=$sr.ComputerName; Status=$sr.Status;
    RdpLocalGroupMembers=($rdpRoots -join ' | ');
    AdministratorsMembers=($adminRoots -join ' | ');
    RdpServiceEnabled=if ($null -eq $sr.RdpEnabled) {'Unknown'} elseif ($sr.RdpEnabled) {'Yes'} else {'No'};
    DetailedRows=$hostRows.Count; ErrorMessage=$sr.ErrorMessage
  })
}

$files = @{
  Summary=Join-Path $runDir '01_Servers_Summary.csv'
  Details=Join-Path $runDir '02_Principals_Expanded.csv'
  Rights=Join-Path $runDir '03_UserRights_Assignments.csv'
  Errors=Join-Path $runDir '04_Errors.csv'
  Principals=Join-Path $runDir '05_Principals_Summary.csv'
}
$summary | Export-Csv -LiteralPath $files.Summary -NoTypeInformation -Delimiter ';' -Encoding UTF8
if ($details.Count) { $details | Export-Csv -LiteralPath $files.Details -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
else { 'ComputerName;Grant;PrivilegeLevel;PrincipalName;PrincipalSID;PrincipalType;AccountEnabled;RootPrincipal;MembershipPath;Depth;DirectMember;LocalGroupSID;RdpServiceEnabled' | Set-Content -LiteralPath $files.Details -Encoding UTF8 }
if ($rightsRaw.Count) { $rightsRaw | Export-Csv -LiteralPath $files.Rights -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
else { 'ComputerName;Right;PrincipalName;PrincipalSID;PrincipalType;AccountEnabled' | Set-Content -LiteralPath $files.Rights -Encoding UTF8 }
if ($principalSummary.Count) { $principalSummary | Export-Csv -LiteralPath $files.Principals -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
else { 'ComputerName;PrincipalName;PrincipalSID;PrincipalType;AccountEnabled;PrivilegeLevel;RdpPolicySignal;GrantedVia;MembershipPaths' | Set-Content -LiteralPath $files.Principals -Encoding UTF8 }
if ($errors.Count) { $errors | Export-Csv -LiteralPath $files.Errors -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
else { 'ComputerName;Stage;Message' | Set-Content -LiteralPath $files.Errors -Encoding UTF8 }
Write-Host "Audit complete. Reports: $runDir" -ForegroundColor Green
$files.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("{0}: {1}" -f $_.Name,$_.Value) }
