# Минимально: Достаточно быть в Remote Management Users на удаленном хосте.
# Оптимально: Добавить пользователя в локальные администраторы или настроить GPO для выдачи нужных прав.
# Поиск учетных данных на целевой машине по маскам файлов

# Параметры
$TargetHost = Read-Host "Введите IP или имя целевого хоста"
$OutputFile = "C:\Reports\Creds_Report_$TargetHost.csv"

# Список ключевых слов для поиска, добавляем сови если надо
$Keywords = @("login", "password", "pass", "credentials", "auth", "user", "pwd", "secret")

# Функция поиска учетных данных в файлах
Function Search-Credentials {
    param (
        [string]$Path
    )
    $Results = @()
    $Files = Get-ChildItem -Path $Path -Recurse -Include "*.txt", "*.csv", "*.log", "*.xml", "*.json", "*.docx" -ErrorAction SilentlyContinue
    foreach ($File in $Files) {
        $Content = Get-Content -Path $File.FullName -Raw -ErrorAction SilentlyContinue
        foreach ($Keyword in $Keywords) {
            if ($Content -match $Keyword) {
                $Results += [PSCustomObject]@{
                    File  = $File.FullName
                    Match = $Keyword
                }
            }
        }
    }
    return $Results
}

# Запуск удаленного сканирования
$ScriptBlock = {
    param ($Keywords)
    $UserProfile = "$env:USERPROFILE"
    $SearchPaths = @("$UserProfile\Documents", "$UserProfile\Desktop", "$UserProfile\Downloads", "C:\Users\Public")
    $Found = @()
    foreach ($Path in $SearchPaths) {
        if (Test-Path $Path) {
            $Found += Search-Credentials -Path $Path
        }
    }
    return $Found
}

# Выполнение на удаленной машине
$FoundCredentials = Invoke-Command -ComputerName $TargetHost -ScriptBlock $ScriptBlock -ArgumentList $Keywords -Credential (Get-Credential)

# Сохранение в отчет
if ($FoundCredentials) {
    $FoundCredentials | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Host "Отчет сохранен в $OutputFile"
} else {
    Write-Host "Учетные данные не найдены."
}
