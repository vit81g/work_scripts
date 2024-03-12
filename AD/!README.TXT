Текст скрипта для PowerShell:
Import-Csv -Path z:\users.csv -Delimiter ',' | ForEach {Get-ADUser -identity $_.user -Server $_.domain -Properties Name,sAMAccountName,extensionAttribute10,Company,Department,extensionAttribute1,extensionAttribute2,title,l,physicalDeliveryOfficeName,mail,description | Select Name,sAMAccountName,extensionAttribute10,Company,Department,extensionAttribute1,extensionAttribute2,title,l,physicalDeliveryOfficeName,mail,description | Export-CSV z:\export_user_list.csv -Delimiter ',' -Append -Encoding UTF8}



Инструкция к скрипту:
1. В excel создаем файл с названием "user", сохраняем его с расширением ".csv".
2. В первой ячейке столбца А вводим текст "domain,user".
3. В ячейках ниже вводим текст "<имя домена в формате cntr.gazprom.loc>,<доменное имя пользователя>" (пример: CNTR.GAZPROM.LOC,GFSAS16).
4. Копируем файл "users.csv" в корень ТФ-Общ/ЦОД-М Windows Explorer/<логин> (File exchange) (Z:).
5. Заходим на ТФ-Общ/RDP-client/c1p1-adm02.gazprom.loc.
6. Запускаем командную строку, вызываем powershell.
7. Копируем строку скрипта из блокнота, выполняем (в тексте скрипта не должно быть переносов на новую строку).
8. Из ТФ-Общ/ЦОД-М Windows Explorer/<логин> (File exchange) (Z:) забираем файл z:\export_user_list.csv
9. Разбиваем итоговые значения по столбцам с разделителем ","



Редактирование Скрипта:
Перечень всех полей, доступных в AD:
  "cn": "Боровков Андрей Владимирович",
      "l": "Москва",
      "title": "главный специалист",
      "description": "Пользователь создан СУУЗ. Источник - АСУП",
      "physicalDeliveryOfficeName": "ул. Большая Черемушкинская, д.13, строение 3  к. 406",
      "telephoneNumber": "2-01-68",
      "instanceType": "4",
      "whenCreated": "20211014084059.0Z",
      "whenChanged": "20220311154808.0Z",
      "displayName": "Боровков Андрей Владимирович",
      "uSNCreated": "113431387",
      "uSNChanged": "128224470"
      "department": "Администрация",
      "company": "ООО \"Газпром информ\"",
      "employeeNumber": "10082961",
      "name": "Боровков Андрей Владимирович",
      "objectGUID": "?\u0014\u0013????M??+\u0013\u0012cJ\u0006",
      "userAccountControl": "262656",
      "employeeID": "03703859",
      "lastLogon": "132912922871507282",
      "pwdLastSet": "132786744599289707",
      "primaryGroupID": "513",
      "objectSid": "\u0001\u0005\u0000\u0000\u0000\u0000\u0000\u0005\u0015\u0000\u0000\u0000\u001b??w?=c????\u0007??\u0002\u0000",
      "accountExpires": "2650467708000000000",
      "logonCount": "126",
      "sAMAccountName": "GFBAV14",
      "sAMAccountType": "805306368",
      "userPrincipalName": "GFBAV14@cntr.gazprom.loc",
      "objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=GAZPROM,DC=LOC",
      "dSCorePropagationData": "20211125124902.0Z,16010101000001.0Z",
      "lastLogonTimestamp": "132907121652872607",
      "msDS-LastSuccessfulInteractiveLogonTime": "132914872624258634",
      "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon": "0",
      "mail": "A.Borovkov@inform.gazprom.ru",
      "extensionAttribute2": "Отдел мониторинга",
      "extensionAttribute10": "GFBAV14",
      "extensionAttribute1": "Упр. контроля эфф-ти мер защиты инф-ции",
      "extensionAttribute9": "87473"
      "memberOf": "CN=CNTR_G_AIB_STI,OU=AIB,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_SUUZ,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_aib_buirg,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_aib_sapriib,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_KROSS,OU=ECP-KROSS,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_SUIP,OU=ECP-SUIP,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_aib_isao,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_SEDUDID,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_ISPRIT,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_C1P2-AUDIT01_USER,OU=ADM,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_ASEZ_PUBLIC_User,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_Naumen_Chrome,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_INFOTECH,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSKIP,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_ASKO,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_CA2_USER_Gazprom_Inform_10012884,OU=CA2 groups,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_PRG_IVS_RDP,OU=PRG,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_PRG_Inform_Outlook,OU=PRG,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SPECREG,OU=Groups,OU=External,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_PRG_1С,OU=PRG,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_RAMPUR,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_MARM,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUST,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSPTP,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSPT,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSPP,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSPD,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSPGK,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSPGIRG,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSMSB,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSI,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_INFRA,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_AIB_IUSNK,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SSH_LIN,OU=LINUX,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_PRG_WinSCP,OU=PRG,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SafeERP_User,OU=SafeERP,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_vCenter_AIB,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_C1P2-ADM02_USER,OU=ADM,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_PRG_PUTTY,OU=PRG,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_STI_AIB,OU=Security Ops,OU=IT Operations,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_PRG_SECURECRT,OU=PRG,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_PDN_INTRNT,OU=Groups,OU=External,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_ASUP_User,OU=ASUP,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_KSC_Adm,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_C1P2-ADM01_USER,OU=ADM,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=ROLE_U_SB_DomainGroupPolicyViewer,OU=SB,OU=Groups,OU=Datacenter,DC=GAZPROM,DC=LOC,CN=CNTR_G_RDP_User,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_C1P1-ADM01_USER,OU=ADM,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_C1P1-ADM03_USER,OU=ADM,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_C1P1-ADM02_USER,OU=ADM,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SUUZ_RM_User,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SUUZ_reports_user_qas,OU=Тестовый контейнер СУУЗ CNTR,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SUUZ_REPORTS_USER,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SPP_USER,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_SUUZ_User,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_CA_User_GazpromInform,OU=CA groups,OU=Groups,DC=CNTR,DC=GAZPROM,DC=LOC,CN=CNTR_G_INTRNT,OU=Groups,OU=External,DC=CNTR,DC=GAZPROM,DC=LOC,CN=ROLE_L_SBLogViewers,OU=Adm Groups,OU=IT Operations,DC=GAZPROM,DC=LOC",




Для редактирования скрипта:
Import-Csv -Path z:\users.csv -Delimiter ',' | ForEach {Get-ADUser -identity $_.user -Server $_.domain -Properties Name,Company,Department | Select Name,Company,Department | Export-CSV z:\export_user_list.csv -Delimiter ',' -Append -Encoding UTF8}
Необходимо добавить в раздел "-Properties" и в раздел "Select" имена полей через запятую без кавычек и пробелов.










