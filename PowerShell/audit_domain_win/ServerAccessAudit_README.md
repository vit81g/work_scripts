# Server Access Audit (PowerShell 5.1)

## Назначение

Аудит назначенных прав на **включённых Windows Server**, обнаруженных по свойству `OperatingSystem` объектов компьютеров в выбранном домене AD. Скрипт опрашивает локальные группы `Administrators` и `Remote Desktop Users` по SID, извлекает назначения прав с помощью `secedit /export /mergedpolicy`, раскрывает группы AD выбранного домена и формирует CSV.

**Не устанавливает фактическую возможность входа по RDP:** не проверяет сетевую доступность TCP/3389, RD Gateway, NLA, firewall, все механизмы токена доступа, условные политики, RDP-сессии и историю входов. Поле `RdpPolicySignal` — только оценка обнаруженных назначений. `UserOrOther` не доказывает отсутствие других привилегий. Некоторые права, группы и вложенности из других доменов не раскрываются. Не используются журналы событий RDP.

## Требования

- Консоль **64-bit Windows PowerShell 5.1** с модулем ActiveDirectory (RSAT).
- Доступ на чтение объектов AD с указанными учётными данными.
- WinRM (обычно 5985/5986, в зависимости от настроек), корректная Kerberos-аутентификация, разрешения на PowerShell Remoting и права выполнять `Get-LocalGroupMember`, `secedit /export` на целевых серверах. В типовой конфигурации могут требоваться локальные административные права.
- Запуск по FQDN, доменные учётные данные. Не рекомендуется включать Basic/AllowUnencrypted или добавлять все машины в TrustedHosts ради работы скрипта.
- Скрипт не изменяет AD, группы и права. На целевом сервере создаёт **только временные файлы** выгрузки INF и журнала, удаляемые после опроса.

## Запуск

```powershell
# Пробный прогон — первые три сервера по имени (не обязательно пилотный OU)
.\Invoke-ServerAccessAudit.ps1 -Domain example.test -MaxServers 3 -ThrottleLimit 3

# Полный прогон — домен запросится интерактивно
.\Invoke-ServerAccessAudit.ps1 -ThrottleLimit 12 -OutputDirectory 'C:\Audit\ServerAccess'
```

Учётные данные вводятся в штатном окне `Get-Credential`; пароль не записывается в скрипт или CSV.

## Структура CSV (UTF-8, разделитель `;`)

| Файл | Гранулярность | Ключевые поля |
|---|---|---|
| `01_Servers_Summary.csv` | 1 строка = сервер | `Number`, `ComputerName`, `Status`, `RdpLocalGroupMembers`, `AdministratorsMembers`, `RdpServiceEnabled`, `DetailedRows`, `ErrorMessage` |
| `02_Principals_Expanded.csv` | 1 строка = право/участник/путь членства | `ComputerName`, `Grant`, `PrivilegeLevel`, `PrincipalName`, `PrincipalSID`, `PrincipalType`, `AccountEnabled`, `RootPrincipal`, `MembershipPath`, `Depth`, `DirectMember`, `LocalGroupSID`, `RdpServiceEnabled` |
| `03_UserRights_Assignments.csv` | 1 строка = прямое назначение права | `ComputerName`, `Right`, `PrincipalName`, `PrincipalSID`, `PrincipalType`, `AccountEnabled` |
| `04_Errors.csv` | 1 строка = ошибка | `ComputerName`, `Stage`, `Message` |
| `05_Principals_Summary.csv` | 1 строка = SID/сервер | `ComputerName`, `PrincipalName`, `PrincipalSID`, `PrincipalType`, `AccountEnabled`, `PrivilegeLevel`, `RdpPolicySignal`, `GrantedVia`, `MembershipPaths` |

`Status=Partial`: хотя бы один этап опроса сервера завершился ошибкой. `Status=Error`: WinRM-сеанс или удалённый вызов не сработал. Некоторые ошибки раскрытия групп AD фиксируются **только** в `04_Errors.csv` и не изменяют статус сервера; проверить ошибки обязательно.

## Интерпретация

- `Administrator` — обнаружено членство в локальной группе Administrators (в том числе по раскрытому пути через AD), но пользователь может быть отключён, право входа запрещено или применяются ограничения UAC.
- `Elevated` — обнаружено назначение одного из выбранных чувствительных user rights, без доказанного членства в Administrators.
- `UserOrOther` — среди найденных назначений отсутствует подтверждение членства в Administrators/выбранных чувствительных прав; **не равно** отсутствию других прав.
- `AllowRightFound_NotVerified` — в отчёте найдено право `SeRemoteInteractiveLogonRight` для этого SID или по раскрытому пути; возможность RDP **не проверена**.
- `DenyRightFound` — найдено `SeDenyRemoteInteractiveLogonRight` для этого SID или по раскрытому пути; результат требует проверки всех политик и членств.
- Неудача разрешения SID не означает отключённую учётную запись. Раскрытие доверенных доменов и локальных групп (кроме 544/555) не реализовано.
- Компьютеры фильтруются по строке `OperatingSystem` в AD; сервер с пустым/некорректным атрибутом будет пропущен, а отключённый объект AD исключён.
- Применять отчёт для управленческого решения следует **после проверки `04_Errors.csv` и выборочного подтверждения на серверах**.

## Документация

- [Get-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember)
- [Get-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember)
- [secedit /export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
- [Allow log on through Remote Desktop Services](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services)
- [Deny log on through Remote Desktop Services](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/deny-log-on-through-remote-desktop-services)

## Проверка

Файл подготовлен и прошёл статическую проверку структуры. **Не могу подтвердить исполнение в доменной среде Windows/AD без доступа к тестовому стенду.** Рекомендуется сначала выполнить прогон по 3 серверам и сверить выборку с `lusrmgr.msc`, `secpol.msc` / `gpresult`.
