################################################################
#                                                              #
# Ajout autonome avancé des utilisateurs à un active Directory #
#                                                              # 
#        Plus d'informations dans ./DevelopperReadme.md        #
#                                                              #
################################################################


Read-Host "/!\ Attention. Ce script est paramétré en fonction de ce que vous rentrez dans la console. Merci de bien faire attention à ce que vous inscrivez. Pour plus d'information, merci de lire 'AdministratorReadMe.md'. [Entrée pour continuer]"

Write-Host ""
Write-Host "Chargement des éléments"
Write-Host "PowerShell ActiveDirectory advanced user configuration V2.0 - Liam Salamagnon - 31/03/2024"
Write-Host "Récupération des sources. Chargement"
Add-Type -AssemblyName System.Windows.Forms
Write-Host "Windows Form a été chargé"

write-host ""
write-host "Veuillez selectionner le fichier CSV à importer"

$initialDirectory = [Environment]::GetFolderPath('Desktop')
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.InitialDirectory = $initialDirectory
$OpenFileDialog.Filter = 'Fichiers CSV (*.csv)|*.csv'
$OpenFileDialog.Multiselect = $false
$response = $OpenFileDialog.ShowDialog( ) # $response can return OK or Cancel
if ( $response -eq 'OK' ) {
    $path = $OpenFileDialog.FileName
}
elseif ($response -eq 'Cancel') {
    Write-Warning "Annulation du script"
    exit
}
else {
    Write-warning "Une erreur est survenue. Merci de contacter Liam Salamagnon"
    exit
}


$AskDelimiter = Read-Host '/!\ Attention, le délimiteur défini est ";". Voulez-vous le modifier ? [Y/Yes/O/Oui] [N/No/Non]'
if ($AskDelimiter -eq "Y" -or $AskDelimiter -eq "Yes" -or $AskDelimiter -eq "O" -or $AskDelimiter -eq "Oui") {
$SelectDelimiter = Read-Host 'Merci de rentrer le délimiteur à utiliser'
$CSVDelimiter = $SelectDelimiter
} else {
$CSVDelimiter = ";"
}
Write-Host $CSVDelimiter

$Password = "a"
$continue = Read-Host "Les utilisateurs devront-ils avoir un mot de passe aléatoire ? [O]ui / [N]on"
if ($continue -eq "N" -or $continue -eq "No" -or $continue -eq "Non") {
    $RandomPass = $false
    while ($Password.Length -lt 8) {
        $Password = Read-Host "Veuillez rentrer un mot de passe à utiliser par défaut (minimum 8 caractères)"
        if ($Password.Length -lt 8) {
            write-warning "Mot de passe trop court"
        }
    }
}
else {
    $RandomPass = $true
}
$continue = Read-Host "Les utilisateurs devront-ils changer leur mot de passe à la première connexion ? [O]ui / [N]on"
if ($continue -eq "N" -or $continue -eq "No" -or $continue -eq "Non") {
    $ChangePassAtLogon = $false
}
else {
    $ChangePassAtLogon = $true
}
$Domaine = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain  
$AdOu = Get-ADOrganizationalUnit -Filter 'Name -eq "Utilisateurs"'
$createOU = $false
if ( $adOu -eq $null) {
    write-warning 'Impossible de trouver une OU "Utilisateurs". Nous la créons.'
    $createOU = $true            
}
write-host ""
write-host "--------------------"
write-host ""
write-host "Récapitulatif :"
write-host ""
write-host "Chemin du fichier CSV : $path"
if ($createOU -eq $true) {
    Write-Host "Emplacement de création des utilisateurs : Une OU 'Utilisateurs', ainsi que ses composantes fonctions, seront créés."
}
else {
    Write-Host "Unité d'organisation maître qui sera utilisé : $adOu"
    Write-Host "/!\ Attention, des unités d'organisations seront créés par fonctions."
}

Write-Host "Domaine AD : $Domaine"
if ($RandomPass -eq $true) {
    Write-Host "Mot de passe des utilisateurs défini sur : Aléatoire"
}
else {
    Write-Host "Mot de passe des utilisateurs défini sur : $Password"
}
if ($ChangePassAtLogon -eq $true) {
    Write-Host "Les utilisateurs devront changer leur mot de passe lors de leur première connexion."
}
write-host ""
write-host "--------------------"
write-host ""
$continue = Read-Host "Voulez-vous continuer ? [O]ui / [N]on"
if ($continue -eq "N" -or $continue -eq "No" -or $continue -eq "Non") {
    write-warning "Script annulé"
    exit
}
else {
    if ($createOU -eq $true) {
        New-ADOrganizationalUnit -Name "Utilisateurs" -ProtectedFromAccidentalDeletion $False
        $AdOu = Get-ADOrganizationalUnit -Filter 'Name -eq "Utilisateurs"'
    }
    write-host $adOu
    Add-Type -AssemblyName System.Web
    Clear-Content "C:\Export.txt"
    Clear-Content "C:\useradd-logs.txt"
    $CSVFile = Import-Csv -Path $path -Delimiter $CSVDelimiter -Encoding UTF8
    $total = 0
    $added = 0
    Foreach ($Utilisateur in $CSVFile) {
        $total += 1
        $Prenom = $Utilisateur.Prenom
        $Nom = $Utilisateur.Nom
        $Login = $Prenom + "." + $Nom
        $Fonction = $Utilisateur.Fonction
        if ($RandomPass) {
            $Password = ([System.Web.Security.Membership]::GeneratePassword(14, 3))
        }
        if (Get-ADUser -Filter { SamAccountName -eq $Login }) {
            Write-Warning "L'utilisateur avec le nom d'utilisateur $Login existe déjà . Génération d'un nom "
            $suffixe = 1
            $nomUtilisateurADOriginal = $Login
            while (Get-ADUser -Filter { SamAccountName -eq $Login }) {
                $Login = $nomUtilisateurADOriginal + "-" + $suffixe
                $suffixe++
            }
            Write-Host "Nouveau nom généré : $Login"
            $Nom = $Nom + "-" + $($suffixe - 1)
        }
        $Mail = $Login + "@" + $Domaine
        $RealAdOu = Get-ADOrganizationalUnit -Filter 'Name -eq $Fonction'
        if ( $RealAdOu -eq $null) {
            New-ADOrganizationalUnit -Name $Fonction -ProtectedFromAccidentalDeletion $False -Path $adOu
            write-host "Unité d'organisation $Fonction créé."
            $RealAdOu = Get-ADOrganizationalUnit -Filter 'Name -eq $Fonction'
                       
        }
        Write-Host " AD OU FINAL : $RealAdOu"

        try {
            $Error.clear()
            New-ADUser `
                -Name "$Nom $Prenom" `
                -DisplayName "$Nom $Prenom" `
                -GivenName $Prenom `
                -Surname $Nom `
                -SamAccountName $Login `
                -UserPrincipalName $Mail `
                -EmailAddress $Mail `
                -Title $Fonction `
                -Path $RealAdOu `
                -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
                -ChangePasswordAtLogon $ChangePassAtLogon `
                -Enabled $True
            Write-Host "Nouvel utilisateur : $Nom $Prenom : $Login / $Password ($Fonction)"
        }
        catch {
            Write-error "$Error"
            Add-Content -Path "C:\useradd-logs.txt" -Value "[ERREUR] (User) : $Error[0]"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> Name : $Nom $Prenom"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> Display Name : $Nom $Prenom"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> GivenName : $Prenom"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> Surname : $Nom"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> SamAccountName : $Login"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> UserPrincipalName : $Mail"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> EmailAddress : $Mail"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> Title : $Fonction"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> Path : $AdOu"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> Password : $Password"
            Add-Content -Path "C:\useradd-logs.txt" -Value "> ChangePasswordAtLogon : $ChangePassAtlogon"
            Add-Content -Path "C:\useradd-logs.txt" -Value " "
        }
        if ( -not $Error) {
                write-host "Recherche de groupe"
                write-host $Fonction
                try {
                $group = Get-ADGroup -Identity $Fonction
                } catch {$group = $null}
                if ($group -eq $null) {
                    $Fonction = $Fonction + "_RW"
                    write-warning "Aucun groupe trouvé. recherche d'un groupe $Fonction"
                    try {
                        $group = Get-ADGroup -Identity $Fonction
                    } catch {$group = $null}
                }
                if ($group -eq $null) {
                    $Fonction = $Utilisateur.Fonction + "_RO"
                    write-warning "Aucun groupe trouvé. recherche d'un groupe $Fonction"
                    try {
                        $group = Get-ADGroup -Identity $Fonction
                    } catch {$group = $null}
                }
                if ($group -eq $null) {
                    write-warning "Impossible de trouver un groupe correspondant. Ouverture du systÃ¨me de crÃ©ation des groupes."
                    write-host "Création d'un groupe utilisateur. Chargement ..."
                    write-host "Recupération du nom de la fonction"
                    $Fonction = $Utilisateur.Fonction
                    write-host "Fonction : $Fonction"
                    write-host "Récupération du conteneur de groupes"
                    $GRPAdOu = Get-ADOrganizationalUnit -Filter 'Name -eq "Groupes"'
                    if ( $GRPadOu -eq $null) {
                        write-warning 'Impossible de trouver une Unité d Organisation "Groupes". Création en cours ...'
                        New-ADOrganizationalUnit -Name "Groupes" -ProtectedFromAccidentalDeletion $true
                        $GRPadOu = Get-ADOrganizationalUnit -Filter 'Name -eq "Groupes"'
                    }
                    $continue = Read-Host "Voulez vous créer un groupe Read & Write (_RW), Read Only (_RO) ou autre (sans extension) ? [RW / 1] / [RO / 2] / [O / 3]"
                    if ($continue -eq "RW" -or $continue -eq "3") {
                        $Fonction = $Fonction + "_RW"                         
                    }
                    elseif ($continue -eq "RO" -or $continue -eq "2") {
                        $Fonction = $Fonction + "_RO"                      
                    }
                    New-ADGroup `
                    -Name "$Fonction" `
                    -GroupScope 2 `
                    -Path $GRPAdOu
                    write-host "Nouveau groupe créé : $Fonction. Stocké dans $GRPadOu"
                }         
            try {
                Add-ADGroupMember `
                    -Identity "$Fonction" `
                    -Members "$Login"
                Write-Host "$Nom $Prenom ajouté au groupe $Fonction"
                Add-Content -Path "C:\Export.txt" -Value "$Nom $Prenom : $Login / $Password ($Fonction)"
                $added += 1
            }
            catch {
                Write-error "$Error"
                Add-Content -Path "C:\useradd-logs.txt" -Value "[ERREUR] (Group) : $Error[0]"
                Add-Content -Path "C:\useradd-logs.txt" -Value "> Identity : $Fonction"
                Add-Content -Path "C:\useradd-logs.txt" -Value "> Members : $Login"
                $Error.Clear()
            }
        }
        else {
            $Error.clear()
        }
    }
    $stat = $total - $added
    Write-Host "Fin du script. $added/$total comptes créés. $stat entrée(s) invalide(s)."
}
