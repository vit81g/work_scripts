$remoteIPAddress = "Введите_IP_адрес_компьютера"
$credential = Get-Credential -Credential "Имя_пользователя"

$scriptBlock = {
    $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $username
}

$remoteUsername = Invoke-Command -ComputerName $remoteIPAddress -Credential $credential -ScriptBlock $scriptBlock
Write-Host "Имя пользователя на компьютере с IP-адресом $remoteIPAddress: $remoteUsername"
