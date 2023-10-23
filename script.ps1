# 1. Affichage des informations générales sur la station :
# • Modèle du matériel,
# • Version Bios ou UEFI,
# • Slot RAM installées, taille de la RAM sur chaque slot,
# • Information sur le processeur,
# • Caractéristiques des cartes réseaux, adresses MAC/IP,
# • Types et nombre des disques durs installés : Information sur les partitions, information
# sur Bitlocker
# • Affichage des réseaux Wifi connus et leurs mots de passes,
# • Version de l’OS, date de l’installation
# • …etc.

#Début du script
#Affichage des informations générales sur la station
#Modèle du matériel
Get-WmiObject -Class Win32_ComputerSystem | Select-Object -Property Model
#Version Bios ou UEFI
Get-WmiObject -Class Win32_BIOS | Select-Object -Property SMBIOSBIOSVersion
#Slot RAM installées, taille de la RAM sur chaque slot
Get-WmiObject -Class Win32_PhysicalMemory | Select-Object -Property BankLabel, Capacity
#Information sur le processeur
Get-WmiObject -Class Win32_Processor | Select-Object -Property Name, NumberOfCores, NumberOfLogicalProcessors
#Caractéristiques des cartes réseaux, adresses MAC/IP
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property Description, MACAddress, IPAddress
#Types et nombre des disques durs installés : Information sur les partitions, information sur Bitlocker
Get-WmiObject -Class Win32_DiskDrive | Select-Object -Property Model, Partitions, Size
#Affichage des réseaux Wifi connus et leurs mots de passes
netsh wlan show profiles
#Version de l’OS, date de l’installation
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property Caption, InstallDate


# 2. Affichage des informations sur les comptes utilisateurs :
# • Informations sur les comptes locaux (privilèges attribués à chaque utilisateur, date de la
# dernière connexion, …etc)
# • Affichage d’un dump de la base SAM
# • Affichage des politiques GPO des comptes et mots de passe et comparaison avec les
# bonnes pratiques CIS
# • Vérifier la conformité des paramètres UAC (User Account Control)

#Affichage des informations sur les comptes utilisateurs
#Informations sur les comptes locaux (privilèges attribués à chaque utilisateur, date de la dernière connexion, …etc)
Get-WmiObject -Class Win32_UserAccount | Select-Object -Property Name, AccountType, Description, Disabled, Lockout, PasswordChangeableDate, PasswordExpires, PasswordRequired, SID, SIDType, Status
#Affichage d’un dump de la base SAM
Get-WmiObject -Class Win32_UserAccount | Select-Object -Property Name, AccountType, Description, Disabled, Lockout, PasswordChangeableDate, PasswordExpires, PasswordRequired, SID, SIDType, Status | Out-File -FilePath C:\Users\Public\Documents\dumpSAM.txt
#Affichage des politiques GPO des comptes et mots de passe et comparaison avec les bonnes pratiques CIS
Get-WmiObject -Class Win32_GroupPolicy | Select-Object -Property Caption, Description, SettingNumber, SettingString, SettingBoolean, SettingDateTime, SettingNumberArr
#Vérifier la conformité des paramètres UAC (User Account Control)
Get-WmiObject -Class Win32_UserAccountControlSetting | Select-Object -Property Caption, Description, SettingNumber, SettingString, SettingBoolean, SettingDateTime, SettingNumberArr


# 3. Affichage et vérification des paramètres du parefeu Windows.
Get-NetFirewallRule
Get-NetFirewallProfile

# 4. Affichage de la liste des services à arrêter en application du principe de minimisation.
# Début
# Affichage de la liste des services à arrêter en application du principe de minimisation
Get-Service | Select-Object -Property Name, DisplayName, Status, StartType, Description | Out-File -FilePath C:\Users\Public\Documents\services.txt

  
