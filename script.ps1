# 1. Affichage des informations générales sur la station :
# Modèle du matériel
Write-Host "Modèle du matériel"
Get-WmiObject -Class Win32_ComputerSystem | Select-Object -Property Model | Write-Host

# Version Bios ou UEFI
Write-Host "Version Bios ou UEFI"
Get-WmiObject -Class Win32_BIOS | Select-Object -Property SMBIOSBIOSVersion | Write-Host

# Slot RAM installées, taille de la RAM sur chaque slot
Write-Host "Slot RAM installées, taille de la RAM sur chaque slot"
Get-WmiObject -Class Win32_PhysicalMemory | Select-Object -Property BankLabel, Capacity | Write-Host

# Information sur le processeur
Write-Host "Information sur le processeur"
Get-WmiObject -Class Win32_Processor | Select-Object -Property Name, NumberOfCores, NumberOfLogicalProcessors | Write-Host

# Caractéristiques des cartes réseaux, adresses MAC/IP
Write-Host "Caractéristiques des cartes réseaux, adresses MAC/IP"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property Description, MACAddress, IPAddress | Write-Host

# Types et nombre des disques durs installés : Information sur les partitions, information sur Bitlocker
Write-Host "Types et nombre des disques durs installés : Information sur les partitions, information sur Bitlocker"
Get-WmiObject -Class Win32_DiskDrive | Select-Object -Property Model, Partitions, Size | Write-Host

# Information sur Bitlocker
Get-BitLockerVolume | Select-Object -Property MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage | Write-Host

# Affichage des réseaux Wifi connus et leurs mots de passes
Write-Host "Affichage des réseaux Wifi connus et leurs mots de passes"
$WlanProfiles = netsh wlan show profiles |
Select-String "Profil " | ForEach-Object { ($_.Line -split ': ', 2)[-1] }
Foreach ($WlanProfile in $WlanProfiles) {
    $KeyProfile = netsh wlan show profile name=$WlanProfile key=clear | Select-String 'Contenu de la'
    $Password = if ($null -ne $KeyProfile) { $KeyProfile.ToString().Split(': ')[-1] }
    [PSCustomObject]@{
        Profile  = $WlanProfile
        Password = $Password
    }
}

# Version de l’OS, date de l’installation
Write-Host "Version de l’OS, date de l’installation"
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property Caption, InstallDate | Write-Host

# 2. Affichage des informations sur les comptes utilisateurs :
# Informations sur les comptes locaux (privilèges attribués à chaque utilisateur, date de la dernière connexion, …etc)
Write-Host "Informations sur les comptes locaux (privilèges attribués à chaque utilisateur, date de la dernière connexion, …etc)"
# Obtenir la liste des comptes locaux
Write-Host "Liste des comptes locaux :"

# Obtenir la liste des comptes locaux
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property NumberOfLicensedUsers, NumberOfUsers, RegisteredUser, LastBootUpTime | Format-Table -AutoSize

# Affichage d’un dump de la base SAM
Write-Host "Affichage d’un dump de la base SAM"
$MimikatzPath = "./mimikatz/Win32/mimikatz.exe"
$MimikatzCommands = 'privilege::debug token::elevate lsadump::sam exit'

Start-Process -FilePath $MimikatzPath -ArgumentList $MimikatzCommands -NoNewWindow

# Wait for the Mimikatz process to exit
$MimikatzProcess = Get-Process -Name "mimikatz"
$MimikatzProcess.WaitForExit()

# Display the message after the Mimikatz process exits
Write-Host "Dump de la base SAM effectué"


# 3. Affichage et vérification des paramètres du pare-feu Windows.
# Check if Windows Firewall is enabled
$firewallEnabled = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'True' }

if ($firewallEnabled) {
    Write-Host "Windows Firewall is enabled."
    # Display Windows Firewall rules
    $firewallRules = Get-NetFirewallRule
    Write-Host "Windows Firewall Rules:"
    $firewallRules | Format-Table -Property Name, DisplayName, Enabled, Action, Direction, Profile, Protocol, LocalPort, RemotePort, LocalAddress, RemoteAddress
    # Display Windows Firewall profile settings
    $firewallProfiles = Get-NetFirewallProfile
    Write-Host "Windows Firewall Profile Settings:"
    $firewallProfiles | Format-Table -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction, Notifications
} else {
    Write-Host "Windows Firewall is disabled."
}

# 4. Affichage de la liste des services à arrêter en application du principe de minimisation.
# Define an array of essential services that you want to exclude from the list
$essentialServices = @(
    "wuauserv", # Windows Update
    "wscsvc",   # Security Center
    "Dnscache"  # DNS Client
    # Add any other services you consider essential
)

# Get a list of all services and filter based on start type
$services = Get-Service | Where-Object { $_.StartType -in @("Automatic", "Manual") -and $_.Status -eq "Running" -and $_.Name -notin $essentialServices }

# Display the list of services that can be stopped
if ($services.Count -gt 0) {
    Write-Host "Services that can be stopped to minimize resource usage:"
    $services | Format-Table -Property DisplayName, Name, Status, StartType
} else {
    Write-Host "No non-essential services are currently running."
}
