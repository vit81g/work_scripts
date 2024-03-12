$sessionInfo = quser /server:127.0.0.1 # замените 127.0.0.1 на IP-адрес сервера или компьютера

# Используем регулярные выражения для извлечения информации об IP-адресах из вывода команды quser
$ipRegex = "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
$matches = $sessionInfo | Select-String -Pattern $ipRegex -AllMatches | ForEach-Object { $_.Matches.Value }

# Вывод информации о сеансах пользователей с соответствующими IP-адресами
foreach ($match in $matches) {
    Write-Host "IP-адрес сеанса пользователя: $match"
}
