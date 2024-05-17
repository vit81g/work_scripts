# Вы должны заменить "C:\Путь\К\Файлу\users.csv" на путь и имя файла, по которому вы хотите сохранить 
# данные пользователей.

# Запустите этот скрипт на компьютере с выполняющейся сеансом PowerShell с правами администратора домена, 
# чтобы получить данные пользователей домена и сохранить их в файле CSV.




# Импортируем модуль Active Directory для работы с учетными записями
Import-Module ActiveDirectory

# Указываем путь и имя файла для сохранения данных
$csvPath = "C:\Путь\К\Файлу\users.csv"

# Получаем всех пользователей домена
$users = Get-ADUser -Filter * -Properties *

# Создаем пустой массив для хранения данных
$results = @()

# Перебираем каждого пользователя
foreach ($user in $users) {
    $userData = New-Object PSObject
    
    # Добавляем свойства пользователя в объект $userData
    $userData | Add-Member -MemberType NoteProperty -Name "Имя" -Value $user.Name
    $userData | Add-Member -MemberType NoteProperty -Name "Логин" -Value $user.SamAccountName
    $userData | Add-Member -MemberType NoteProperty -Name "Отдел" -Value $user.Department
    $userData | Add-Member -MemberType NoteProperty -Name "Должность" -Value $user.Title
    $userData | Add-Member -MemberType NoteProperty -Name "Email" -Value $user.EmailAddress
    $userData | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $user.Enabled
    $userData | Add-Member -MemberType NoteProperty -Name "lastlogontimestamp" -Value   $user.lastlogontimestamp
    $userData | Add-Member -MemberType NoteProperty -Name "PasswordExpired" -Value $user.PasswordExpired
    $userData | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $user.PasswordLastSet
    $userData | Add-Member -MemberType NoteProperty -Name "PasswordNeverExpires" -Value $user.PasswordNeverExpires
    
    
    # Добавляем объект $userData в массив $results
    $results += $userData
}

# Экспортируем данные в CSV-файл
$results | Export-Csv -Delimiter ',' -Append -Encoding UTF8 $csvPath -NoTypeInformation 

Write-Host "Данные успешно экспортированы в файл CSV ($csvPath)"
