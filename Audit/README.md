# AD Advanced Audit

Framework PowerShell d'audit et d'analyse approfondie d'Active Directory.

## Garantie

Le script est concu en **lecture seule** : aucune creation, modification ou suppression d'objet AD, GPO, DNS, ACL, compte ou groupe. Un seul fichier de sortie maximum est produit par execution : `AD-Audit.json` (ou `AD-Audit.html` si HTML est choisi).

## Modules

### Inventaire

- Users — comptes, groupes directs/recursifs, privileges, dernier logon, verrouillage, mots de passe, UAC, Kerberos, delegation, SPN.
- Groups — groupes, portee, type, membres directs/recursifs et groupes privilegies.
- Computers — OS, connexions, inactivite, delegation et SPN.
- OUs — OU, protection contre suppression accidentelle et GPO liees.
- GPOs — inventaire GPO et etat.
- Domain — domaine/foret et politique de mots de passe.
- DCs — controleurs de domaine.
- Sites — sites, subnets et liens.
- Trusts — relations de confiance.
- DNS — zones DNS.
- Schema — objets du schema AD.

### Analyse securite

- Privileged — groupes sensibles et membres recursifs.
- Kerberos — AS-REP roastable, delegation non contrainte, comptes portant des SPN.
- PasswordPolicies — politique de domaine et FGPP.
- LAPS — couverture Legacy LAPS / Windows LAPS.
- AdminSDHolder — ACL du conteneur de protection des comptes privilegies.
- Delegation — ACL de la racine du domaine.
- ADCS — detection des objets AD CS / templates.
- RecycleBin — etat de la corbeille AD.
- Health — replication AD.
- GPOAnalysis — analyse de plusieurs parametres sensibles dans les rapports GPO.

## Utilisation

Mode interactif :

    .\Invoke-ADAudit.ps1

Tout auditer :

    .\Invoke-ADAudit.ps1 -Mode All

Selection directe :

    .\Invoke-ADAudit.ps1 -Modules Users,Groups,Kerberos,GPOAnalysis,Health

Cibler un DC :

    .\Invoke-ADAudit.ps1 -Modules Users,Groups,Health -DomainController dc01.example.local

Export HTML unique :

    .\Invoke-ADAudit.ps1 -Mode All -ExportFormat HTML

## Findings

Les anomalies sont centralisees dans `Findings` avec Severity, Category, Title, Object, Details et Recommendation. Les niveaux vont de Critical a Info.

Les findings sont des indications d'audit : ils doivent etre valides avec le contexte de l'environnement.

## Prerequis

- Windows PowerShell 5.1 ou PowerShell 7.
- RSAT Active Directory / module ActiveDirectory.
- GroupPolicy pour les GPO.
- DnsServer pour DNS.
- Droits de lecture suffisants.

## Donnees sensibles

Un audit AD peut contenir des noms, UPN, groupes privilegies, structure OU, SPN, configuration de securite et informations PKI. Ne publiez jamais un export issu d'une infrastructure reelle dans un depot public.

## Evolutions

- analyse complete des parametres GPO ;
- analyse ACL avancee avec chemins d'escalade ;
- analyse des comptes de service ;
- audit Kerberos approfondi ;
- audit AD CS complet ;
- analyse DNS avancee ;
- scoring RSSI ;
- comparaison de deux audits ;
- contrôles CIS / ANSSI avec evidence ;
- chemins d'administration tiering ;
- permissions dangereuses sur objets AD.
