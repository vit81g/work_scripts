# рабочий
# Введите имя компьютера или IP-адрес
$ComputerName = Read-Host "Введите имя компьютера или IP-адрес"

# Получаем информацию о компьютере
$ComputerInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName

# Выводим имя пользователя
Write-Host "Имя пользователя: $($ComputerInfo.UserName)"
