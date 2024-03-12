# Подключение к домену Active Directory
Import-Module ActiveDirectory

# Получение списка пользователей с правами администратора
$adminUsers = Get-ADUser -Filter * -Property MemberOf |
             Where-Object { $_.MemberOf -like '*Administrators*' } |
             Select-Object Name, SamAccountName

# Экспорт списка пользователей в CSV-файл
$adminUsers | Export-Csv -Path "C:\path\to\file.csv" -NoTypeInformation


# Для выполнения скрипта, у вас должны быть установлены модуль Active Directory и права доступа для чтения # информации о пользователях в домене.

# Пожалуйста, замените "C:\path\to\file.csv" на путь, по которому вы хотите сохранить файл CSV с 
# результатами. Убедитесь, что у вас есть соответствующие разрешения на запись в эту директорию.
