# Définir l'encodage en UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "######################################################"
Write-Host "#                                                    #"
Write-Host "#     Outil de création Assisté - Powershell 100     #"
Write-Host "#        Par Liam Salamagnon - Logs : Bureau         #"
Write-Host "#                                                    #"
Write-Host "######################################################"

# Chargement des assemblies nécessaires
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Web
Import-Module ActiveDirectory

#Définition d'un dossier de base
$initialDirectory = [Environment]::GetFolderPath('Desktop')
try {
    Clear-Content "$initialDirectory\UserList.txt" #Suppression du contenu du fichier listage utilisateurs créé
} catch {
    throw $_
}


function UserLogging { #Fonction de log des utilisateurs créés
    param (
        [string]$Username,
        [string]$Pass,
        [string]$Group
    )
    Add-Content -Path "$initialDirectory\UserList.txt" -Value "Utilisateur : $Username - Mot de passe : $Pass - Service : $Group"

}

function Error { #Fonction de notification des erreurs
    param (
        [string]$Key,
        [bool]$Abort = $false
    )

    # Table d'erreurs
    $ErrorTable = @{
        "001" = "Le serveur Active Directory n'est pas joignable. Veuillez vérifier votre connexion.";
        "002" = "Votre machine n'est pas liée à un serveur Active Directory.";
        "003" = "Vous ne disposez pas des droits d'administration sur votre domaine.";
        "004" = "Une erreur est survenue durant la vérification de vos permissions. Merci de réessayer en tant qu'administrateur";
        "005" = "Clé inconnue. Veuillez vérifier la clé d'erreur.";
        "006" = "La création de l'utilisateur a échoué"
    }

    #Récupération du message d'erreur
    if ($ErrorTable.ContainsKey($Key)) {
        $ErrorMessage = $ErrorTable[$Key]
    } else {
        $ErrorMessage = $ErrorTable["E005"]
    }

    # Affichage du message d'erreur dans Pop-up
    [System.Windows.Forms.MessageBox]::Show($ErrorMessage, "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)

    if ($Abort) { #Si abort true, on kill le script
        Exit
    }
}

function IsInDomain { #Vérifier que l'ordinateur est dans un domaine
    $ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem

    if (-not $ComputerInfo.PartOfDomain) {
        Error -Key "002" -Abort $true
    }
}
function IsDomainPingable {# Vérification que le domaine AD est pingable
        # Vérifie le contrôleur de domaine de la machine locale
        $domainController = (Get-ADDomainController -Discover -Domain (Get-ADDomain).DNSRoot).Name

        # Teste la connectivité avec le contrôleur de domaine
        $pingResult = Test-Connection -ComputerName $domainController -Count 2 -Quiet
    
        # Si le contrôleur de domaine n'est pas joignable, notifie l'utilisateur
        if (-not $pingResult) {
            Error -Key "001" -Abort $true
        }
}
function IsAdminDomaine {# Vérifier que l'utilisateur est administrateur du domaine
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent() # Récupération de l'utilisateur actuel
        $principal = New-Object System.Security.Principal.WindowsPrincipal($user) #Récupération des permissions de l'utilisateur actuel
        
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { # Vérifier si la permission Administrateur est présente
            Error -Key "003" -Abort $true
        }
    } catch {
        Error -Key "004" -Abort $true
    }
}
function CreateService { #Création de service
    param (
        [string]$Name,
        [bool]$Silent = $false
    )



    # Vérifier si l'OU existe
    if (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'") {
        [System.Windows.MessageBox]::Show("L'unité d'organisation $Name est déjà créée.", "Erreur serveur", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    } else {
        # Créer l'OU parent si nécessaire
        if (-not (Get-ADOrganizationalUnit -Filter { Name -eq 'Services' })) {
            try {
            New-ADOrganizationalUnit -Name "Services" -ProtectedFromAccidentalDeletion $true
            } catch {
                throw $_
            }
        }

        # Récupérer l'OU "Services"
        $servicesOU = Get-ADOrganizationalUnit -Filter { Name -eq 'Services' }
        $servicesPath = $servicesOU.DistinguishedName

        # Créer l'OU pour le service
        New-ADOrganizationalUnit -Name $Name -ProtectedFromAccidentalDeletion $true -Path $servicesPath
    }

    # Vérifier si le groupe existe
    if (Get-ADGroup -Filter "Name -eq '$Name'") {
        [System.Windows.MessageBox]::Show("Le groupe de service $Name existe déjà.", "Erreur serveur", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    } else {
            # Définir le chemin du partage
    $FolderPath = "\\vm-ad\Data\Services\$Name"
        # Créer le groupe dans l'OU 'Services'
        New-ADGroup -Name $Name -SamAccountName $Name -GroupCategory Security -GroupScope Global -Path "OU=$Name,$servicesPath"
        # Créer le dossier si nécessaire
    if (-not (Test-Path -Path $FolderPath)) {
        New-Item -Path $FolderPath -ItemType Directory
        Write-Host "Dossier créé : $FolderPath"
        # Configurer les autorisations
    try {
        # Supprimer les autorisations existantes
        $acl = Get-Acl -Path $FolderPath
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

        # Ajouter les autorisations pour le groupe Service
        $accessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$Name", "Read,Write", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($accessRule1)

        # Ajouter les autorisations pour les administrateurs
        $accessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateurs", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($accessRule2)

        # Appliquer les modifications
        Set-Acl -Path $FolderPath -AclObject $acl
        if(-not $Silent) {
            [System.Windows.Forms.MessageBox]::Show("Le service $Name a été correctement ajouté", "Notification")
        }
    } catch {
        Write-Error "Erreur lors de la configuration des autorisations : $_"
    }
    } else {
        Write-Host "Le dossier existe déjà : $FolderPath"
    }
    }

    

    
}

function CreateADUser { #Fonction de création de l'utilisateur
    param(
        [string]$Name,
        [string]$LastName,
        [string]$Service,
        [bool]$Silent = $false
    )
    # Vérifier et créer l'OU si nécessaire
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Service'")) {
        CreateService -Name $Service -Silent $Silent
    }
    $FinalOU = Get-ADOrganizationalUnit -Filter "Name -eq '$Service'"

    # Réduction de la longueur du LastName si nécessaire
    $TrunkLastName = if ($LastName.Length -gt 17) { $LastName.Substring(0, 17) } else { $LastName }

    # Génération du login
    $Login = ($Name.Substring(0,1) + "." + $TrunkLastName).ToLower()

    # Gestion des doublons de logins
    $OriginalLogin = $Login
    $suffixe = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$Login'") {
        $Login = "$OriginalLogin$suffixe"
        $suffixe++
    }
    # Génération d'un mot de passe
    $Password = [System.Web.Security.Membership]::GeneratePassword(14, 3)
    Write-Output $Password

    try {# Création de l'utilisateur
        New-ADUser `
            -Name "$LastName $Name" `
            -DisplayName "$LastName $Name" `
            -GivenName $Name `
            -Surname $LastName `
            -SamAccountName $Login `
            -UserPrincipalName $Email `
            -Title $Service `
            -Enabled $true `
            -HomeDirectory "\\vm-ad\Data\Utilisateurs\$Login" `
            -HomeDrive "U:" `
            -Path $FinalOU.DistinguishedName `
            -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
            -ChangePasswordAtLogon $true 

            New-Item -ItemType Directory -Path "\\vm-ad\Data\Utilisateurs\$Login"
            $acl = Get-Acl "\\vm-ad\Data\Utilisateurs\$Login"
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Login", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($AccessRule)
            Set-Acl "\\vm-ad\Data\Utilisateurs\$Login" $acl
            if(-not $Silent) {
                [System.Windows.Forms.MessageBox]::Show("Utilisateur $Login créé avec le mot de passe $Password", "Notification")
            }
    } catch {
        Error -Key "006"
    }

    # Logging des informations utilisateur
    UserLogging -Username $Login -Pass $Password -Group $Service
}

function Get-Delimiter { #Récupération automatique des délimiteurs CSV / XLSX
    param (
        [string]$filePath
    )

    try {
        # Vérifier si c'est un fichier CSV
        if ($filePath -like "*.csv") {
            $line = Get-Content -Path $filePath | Select-Object -First 1
            $delimiters = @(",", ";", "`t", "|")

            foreach ($delimiter in $delimiters) {
                $count = ($line -split $delimiter).Count
                if ($count -gt 1) {
                    return $delimiter
                }
            }
            throw "Aucun délimiteur valide trouvé pour le fichier CSV."
        }

        # Si c'est un fichier Excel
        elseif ($filePath -like "*.xlsx") {
            return ","
        }

        # Si le format n'est pas pris en charge
        else {
            throw "Le fichier n'est pas un format pris en charge (CSV ou Excel)."
        }
    } catch {
        Write-Host "Erreur dans Get-Delimiter : $_"
        throw $_
    }
}

# Fonction pour traiter les colonnes CSV ou Excel
function ProcessCsv {
    param (
        [string]$filePath
    )

    try {
        $delimiter = Get-Delimiter -filePath $filePath
        # Si c'est un CSV, on lit et traite les lignes avec un encodage explicite
        if ($filePath -like "*.csv") {
            $csvData = Import-Csv -Path $filePath -Delimiter $delimiter -Encoding UTF8
        }

        # Si c'est un fichier Excel
        elseif ($filePath -like "*.xlsx") {
            if (-not (Get-Module -ListAvailable -Name ImportExcel)) { #Si le module n'est pas existant, on l'installe
                Install-Module -Name ImportExcel -Force -Scope CurrentUser
            }            # Utilisation du module ImportExcel pour charger les données Excel
            $csvData = Import-Excel -Path $filePath

            # Vérification du contenu du fichier pour débogage
            if ($csvData.Count -eq 0) {
                throw "Le fichier Excel est vide ou mal formaté."
            }
        }

        # Vérifier si les données ont bien été importées
        if (-not $csvData) {
            throw "Les données n'ont pas pu être chargées. Vérifiez le fichier."
        }
        return $csvData
    } catch {
        Write-Host "Erreur dans ProcessCsv : $_"
        throw $_
    }
}
function MassiveAdd {
    
    # Fenêtre GUI
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = $initialDirectory
    $OpenFileDialog.Filter = 'Fichiers Excel (*.xlsx)|*.xlsx|Fichiers CSV (*.csv)|*.csv'
    $OpenFileDialog.Multiselect = $false
    $response = $OpenFileDialog.ShowDialog()

    if ($response -eq 'OK') {
        $path = $OpenFileDialog.FileName

        # Traiter le fichier et récupérer les données
        try {
            $csvData = ProcessCsv -filePath $path
        } catch {
            Error -Key "Erreur lors du traitement du fichier" -Abort $true
        }

        # Vérifier si les données contiennent les colonnes attendues
        $requiredColumns = @("Prénom", "Nom", "Services")
        $missingColumns = $requiredColumns | Where-Object { $_ -notin $csvData[0].PSObject.Properties.Name }

        if ($missingColumns.Count -gt 0) {
            # Afficher un message d'erreur si des colonnes sont manquantes
            [System.Windows.Forms.MessageBox]::Show("Colonnes manquantes: " + ($missingColumns -join ", "), "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        } else {
            # XAML pour la fenêtre GUI
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" 
        Title="CSV Data" Height="400" Width="500" WindowStartupLocation="CenterScreen" 
        Background="#FFF8E1">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/> <!-- Nouvelle rangée pour les boutons -->
        </Grid.RowDefinitions>

        <!-- Description -->
        <TextBlock Text="Données du fichier CSV" FontSize="16" FontWeight="Bold" HorizontalAlignment="Center" Margin="0,10,0,10" Foreground="#333333"/>

        <!-- Affichage des données CSV -->
        <ListView Name="CSVListView" Grid.Row="1" Margin="0,10">
            <ListView.View>
                <GridView>
                    <GridViewColumn Header="Nom" DisplayMemberBinding="{Binding Nom}" Width="150"/>
                    <GridViewColumn Header="Prénom" DisplayMemberBinding="{Binding Prénom}" Width="150"/>
                    <GridViewColumn Header="Service" DisplayMemberBinding="{Binding Services}" Width="150"/>
                </GridView>
            </ListView.View>
        </ListView>

        <!-- Boutons -->
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="10">
            <Button Name="LancerButton" Content="Lancer" Width="100" Height="30" Margin="10"/>
            <Button Name="AnnulerButton" Content="Annuler" Width="100" Height="30" Margin="10"/>
        </StackPanel>
    </Grid>
</Window>
"@

            # Chargement du XAML
            $reader = (New-Object System.Xml.XmlNodeReader $xaml)
            $window = [Windows.Markup.XamlReader]::Load($reader)

            # Affichage des données CSV dans la ListView
            $csvListView = $window.FindName("CSVListView")
            $csvListView.ItemsSource = $csvData

            # Gestion des événements des boutons
            $lancerButton = $window.FindName("LancerButton")
            $lancerButton.Add_Click({
                # Créer une fenêtre de progression
                $progressWindow = New-Object System.Windows.Window
                $progressWindow.Title = "Création des utilisateurs en cours"
                $progressWindow.Width = 300
                $progressWindow.Height = 150
                $progressWindow.WindowStartupLocation = 'CenterScreen'
            
                # Ajouter une barre de progression à la fenêtre
                $progressBar = New-Object System.Windows.Controls.ProgressBar
                $progressBar.Width = 250
                $progressBar.Height = 30
                $progressBar.Minimum = 0
                $progressBar.Maximum = $csvData.Count
                $progressBar.Value = 0
                $progressBar.IsIndeterminate = $false
            
                # Ajouter la barre de progression à la fenêtre
                $progressWindow.Content = $progressBar
                $progressWindow.Show()
            
                # Compter les utilisateurs traités
                $counter = 0
            
                foreach ($entry in $csvData) { #Pour chaque entrée utilisateur (ligne)
                    try {
                        # Appel de la fonction pour créer l'utilisateur
                        CreateADUser -Name $($entry.Prénom) -LastName $($entry.Nom) -Service $($entry.Services) -Silent $true
            
                        # Mettre à jour la barre de progression
                        $counter++
                        $progressBar.Value = $counter
            
                        # Vérifier si le traitement est terminé
                        if ($counter -eq $csvData.Count) {
                            [System.Windows.MessageBox]::Show("Tous les utilisateurs ont été créés avec succès.", "Opération terminée", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                        }
                    }
                    catch {
                        Error -Key "006"
                    }
                }
            
                $progressWindow.Close()
            })

            $annulerButton = $window.FindName("AnnulerButton")
            $annulerButton.Add_Click({
                $window.Close()
            })

            # Affichage de la fenêtre
            $window.ShowDialog()
        }
    }
}

function AddUserGUI {
    $domain = (Get-ADDomain).DistinguishedName

    # Récupérer les unités d'organisation sous l'OU Services

    $ouList = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Services,$domain" | Where-Object { $_.Name -ne "Services" } | Select-Object -ExpandProperty Name

    # Vérifier si des OUs ont été récupérées
    if ($ouList.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Aucune unité d'organisation (OU) n'a été trouvée sous l'OU 'Services'.", "Erreur", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }

[xml]$xaml = @"
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Formulaire de saisie"
        Width="450" Height="350"
        WindowStartupLocation="CenterScreen">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Prénom -->
        <Label Content="Prénom de l'utilisateur:" Margin="10,10,10,5" Grid.Row="2"/>
        <TextBox Name="TextBoxPrenom" Margin="10,5" Grid.Row="3"/>

        <!-- Nom de l'utilisateur -->
        <Label Content="Nom de l'utilisateur:" Margin="10,10,10,5" Grid.Row="0"/>
        <TextBox Name="TextBoxNom" Margin="10,5" Grid.Row="1"/>

        <!-- Liste déroulante des OU -->
        <Label Content="Sélectionnez une OU:" Margin="10,10,10,5" Grid.Row="4"/>
        <ComboBox Name="ComboBoxOU" Margin="10,5" Grid.Row="5"/>

        <!-- Espace entre les boutons -->
        <Label Content="" Grid.Row="6"/>

        <!-- Bouton "Exécuter" -->
        <Button Name="ButtonExec" Content="Exécuter" Width="100" Height="30" Background="LightGreen" Margin="10,0" Grid.Row="7" HorizontalAlignment="Left"/>

        <!-- Bouton "Annuler" -->
        <Button Name="ButtonCancel" Content="Annuler" Width="100" Height="30" Background="LightCoral" Margin="10,0" Grid.Row="7" HorizontalAlignment="Right"/>
    </Grid>
</Window>
"@
    
    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    $TextBoxNom = $window.FindName("TextBoxNom")
    $TextBoxPrenom = $window.FindName("TextBoxPrenom")
    $ComboBoxOU = $window.FindName("ComboBoxOU")
    $ButtonExec = $window.FindName("ButtonExec")
    $ButtonCancel = $window.FindName("ButtonCancel")

    $ComboBoxOU.ItemsSource = $ouList #REmplir la liste déroulante avec les OU récupérés

    $ButtonExec.Add_Click({
        $firstName = $TextBoxPrenom.Text
        $lastName = $TextBoxNom.Text
        $selectedOU = $ComboBoxOU.SelectedItem

        # Vérifier si tous les champs sont remplis
        if ([string]::IsNullOrEmpty($firstName) -or [string]::IsNullOrEmpty($lastName) -or [string]::IsNullOrEmpty($selectedOU)) {
            [System.Windows.MessageBox]::Show("Veuillez remplir tous les champs et sélectionner une unité d'organisation.", "Erreur de saisie", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        CreateADUser -Name $firstName -LastName $lastName -Service $selectedOU 
    })

    $ButtonCancel.Add_Click({
        $window.Close()
    })

    $window.ShowDialog()
}

function AddServiceGUI {    
[xml]$xaml = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Formulaire de saisie"
        Width="450" Height="350"
        WindowStartupLocation="CenterScreen">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Nom du département -->
        <Label Content="Nom du département:" Margin="10,10,10,5" Grid.Row="2"/>
        <TextBox Name="TextBoxService" Margin="10,5" Grid.Row="3"/>

        <!-- Espace entre les boutons -->
        <Label Content="" Grid.Row="6"/>

        <!-- Bouton "Exécuter" -->
        <Button Name="ButtonExec" Content="Exécuter" Width="100" Height="30" Background="LightGreen" Margin="10,0" Grid.Row="7" HorizontalAlignment="Left"/>

        <!-- Bouton "Annuler" -->
        <Button Name="ButtonCancel" Content="Annuler" Width="100" Height="30" Background="LightCoral" Margin="10,0" Grid.Row="7" HorizontalAlignment="Right"/>
    </Grid>
</Window>
"@
    
        $reader = (New-Object System.Xml.XmlNodeReader $xaml)
        $window = [Windows.Markup.XamlReader]::Load($reader)
    
        $ComboBoxOU = $window.FindName("TextBoxService")
        $ButtonExec = $window.FindName("ButtonExec")
        $ButtonCancel = $window.FindName("ButtonCancel")
    
        $ButtonExec.Add_Click({
            $selectedOU = $ComboBoxOU.Text
    
            # Vérifier si tous les champs sont remplis
            if ([string]::IsNullOrEmpty($selectedOU)) {
                [System.Windows.MessageBox]::Show("Veuillez remplir tous les champs", "Erreur de saisie", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                return
            }
            
            #Création des services
            CreateService -Name $selectedOU 
        })
    
        $ButtonCancel.Add_Click({
            $window.Close()
        })
    
        $window.ShowDialog()
    }

function Main {
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Création de service et utilisateurs"
        Width="450" Height="350" WindowStartupLocation="CenterScreen"
        Background="#FFF8E1">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Description -->
        <TextBlock Text="Outil de création de Compte et Service Active Directory" 
                   FontSize="16" FontWeight="Bold" 
                   HorizontalAlignment="Center" 
                   Margin="0,10,0,10"/>
        <TextBlock Text="Veuillez choisir une action à effectuer en utilisant les boutons ci-dessous." 
                   Grid.Row="0" 
                   TextWrapping="Wrap" 
                   HorizontalAlignment="Center" 
                   Margin="0,0,0,10"/>
        
        <!-- Boutons -->
        <StackPanel Grid.Row="1" Orientation="Vertical" HorizontalAlignment="Center" VerticalAlignment="Center">
            <Button Name="CreateUser" Content="Créer un utilisateur" Width="150" Height="40" Margin="5" Background="#FFB74D" Foreground="Black" FontWeight="Bold"/>
            <Button Name="CreateService" Content="Créer une nouvelle équipe" Width="150" Height="40" Margin="5" Background="#FFB74D" Foreground="Black" FontWeight="Bold"/>
            <Button Name="MassiveAdd" Content="Faire un ajout de masse" Width="150" Height="40" Margin="5" Background="#FFB74D" Foreground="Black" FontWeight="Bold"/>
            <Button Name="CancelButton" Content="Annuler" Width="150" Height="40" Margin="5" Background="#D32F2F" Foreground="White" FontWeight="Bold"/>
        </StackPanel>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)


$window.FindName("CreateUser").Add_Click({ AddUserGUI })
$window.FindName("CreateService").Add_Click({ AddServiceGUI })
$window.FindName("MassiveAdd").Add_Click({ MassiveAdd })
$window.FindName("CancelButton").Add_Click({$window.Close()})

$window.ShowDialog()
}


IsInDomain
IsAdminDomaine
IsDomainPingable
main
