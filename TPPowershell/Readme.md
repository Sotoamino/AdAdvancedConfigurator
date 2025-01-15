# TP PowerShell : Gestion Active Directory

## Objectif
Ce TP a pour objectif d'apprendre à manipuler des objets Active Directory à l'aide de scripts PowerShell. Vous serez amené à effectuer différentes tâches d'administration telles que la gestion des utilisateurs, des groupes, et des unités organisationnelles.

## Prérequis
Avant de commencer, assurez-vous que l'environnement est configuré comme suit :

### Configuration de la machine virtuelle
1. La machine virtuelle doit être configurée comme un **contrôleur de domaine Active Directory**.
2. **Nom de la VM** : `vm-ad`.
3. **Nom de domaine** : `isec.ad`.
4. La VM doit être reliée à Internet pour permettre les mises à jour et la récupération de modules ou packages nécessaires.

### Logiciels nécessaires
- **Windows Server** (recommandé : Windows Server 2019 ou plus récent).
- **PowerShell** (version 5.1 ou plus récente est recommandée).
- **Framework NuGet** : Nécessaire pour installer certains modules PowerShell.
  - Installation de NuGet dans PowerShell :
    ```powershell
    Install-PackageProvider -Name NuGet -Force
    ```

### Configuration réseau
- La machine doit être connectée à un réseau permettant la résolution DNS et les communications liées à Active Directory.
- Activez l'accès Internet pour les installations nécessaires via PowerShell.

### Modules PowerShell
Les modules suivants doivent être disponibles :
- **Active Directory** : Utilisé pour interagir avec les objets AD.
  - Installation :
    ```powershell
    Install-WindowsFeature RSAT-AD-PowerShell
    ```
- **NuGet Provider** : Assurez-vous qu'il est installé pour faciliter la récupération des modules via PowerShell Gallery.

## Instructions
1. **Démarrez la VM** nommée `vm-ad`.
2. Connectez-vous avec un compte ayant les droits d’administrateur du domaine.
3. Installez les modules nécessaires si ce n'est pas déjà fait :
    ```powershell
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name ActiveDirectory -Force
    ```
4. Exécutez les scripts PowerShell fournis pour effectuer les tâches demandées.

## Points de contrôle
- Assurez-vous que le domaine `isec.ad` est fonctionnel.
- Vérifiez que les utilisateurs et groupes créés via les scripts sont visibles dans la console Active Directory Users and Computers.

## Aide et dépannage
Si vous rencontrez des problèmes :
1. Vérifiez que le rôle Active Directory Domain Services est installé.
2. Assurez-vous que le service DNS est configuré et fonctionne correctement.
3. Vérifiez que **NuGet** est bien installé et fonctionnel :
    ```powershell
    Get-PackageProvider -Name NuGet
    ```
4. Utilisez les commandes suivantes pour diagnostiquer des problèmes communs :
   - `Test-ComputerSecureChannel` : Vérifie si la machine est correctement liée au domaine.
   - `Get-ADDomain` : Vérifie les informations du domaine actif.
   - `Get-ADUser` et `Get-ADGroup` : Vérifiez les objets créés.

## Références
- [Documentation PowerShell Active Directory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)
- [Documentation NuGet Provider](https://learn.microsoft.com/en-us/powershell/scripting/gallery/overview)
- [Configuration d'un contrôleur de domaine Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds-deployment)

---

**Note** : Ce TP est conçu pour un environnement de laboratoire et ne doit pas être utilisé en production sans validation préalable.
