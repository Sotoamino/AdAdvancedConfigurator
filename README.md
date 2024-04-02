# Tutoriel d'utilisation du script PowerShell pour l'ajout avancé d'utilisateurs à un Active Directory

Ce tutoriel vous guidera à travers l'utilisation du script PowerShell fourni pour ajouter des utilisateurs à un Active Directory de manière avancée. Assurez-vous de suivre attentivement les instructions pour éviter les erreurs.

## Prérequis

Avant de commencer, assurez-vous de disposer des éléments suivants :

- Un environnement Windows avec PowerShell installé.
- Les autorisations nécessaires pour exécuter des scripts PowerShell et modifier l'Active Directory.
- Un fichier CSV contenant les informations des utilisateurs à ajouter.

## Étapes

### 1. Téléchargement du script

Téléchargez le script fourni dans un emplacement accessible sur votre système.

### 2. Exécution du script

- Ouvrez PowerShell en tant qu'administrateur.
- Naviguez jusqu'à l'emplacement où le script est téléchargé en utilisant la commande `cd` (Change Directory).
- Exécutez le script en utilisant la commande `.\NomDuScript.ps1`. (Assurez-vous de remplacer "NomDuScript" par le nom réel du script)

### 3. Suivez les instructions

- Lorsque le script démarre, suivez les instructions affichées dans la console.
- Sélectionnez le fichier CSV contenant les informations des utilisateurs.
- Vous pouvez également personnaliser certains paramètres tels que le délimiteur CSV et la génération de mots de passe aléatoires.
- Le script affichera un récapitulatif des options sélectionnées.
- Confirmez votre choix pour continuer ou annuler l'exécution du script.

### 4. Analyse des résultats

- Une fois le script terminé, il affichera un compte rendu indiquant le nombre d'utilisateurs créés avec succès et le nombre d'erreurs rencontrées.
- Consultez les fichiers de logs générés pour des informations détaillées sur les erreurs, le cas échéant.
