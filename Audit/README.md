# AD Advanced Audit

Framework PowerShell modulaire d'audit Active Directory en lecture seule.

## Modules

- Users — comptes, groupes directs/récursifs, type de compte, privilèges, dernier logon, verrouillage, expiration, mot de passe, UAC, Kerberos, délégation et SPN.
- Groups — groupes, portée, type, membres directs/récursifs, groupes privilégiés.
- Computers — OS, connexions, inactivité, délégation et SPN.
- OUs — OU, protection contre suppression accidentelle et GPO liées.
- GPOs — inventaire des GPO et rapports XML avec `-IncludeGPOReports`.
- Domain — domaine/forêt, niveaux fonctionnels et stratégie de mots de passe/verrouillage.
- DCs — contrôleurs de domaine, GC, RODC, site et OS.
- Sites — sites, subnets et site links.
- Trusts — relations de confiance.
- DNS — zones DNS si le module DnsServer est disponible.
- Delegation — ACE de la racine du domaine.
- SPNs — SPN portés par les utilisateurs.
- LAPS — couverture Legacy LAPS / Windows LAPS.
- Health — métadonnées de réplication et échecs.

## Utilisation

`.Invoke-ADAudit.ps1` — mode interactif.

`.Invoke-ADAudit.ps1 -Mode All` — tous les modules.

`.Invoke-ADAudit.ps1 -Modules Users,Groups,GPOs,Domain,Health` — sélection non interactive.

`.Invoke-ADAudit.ps1 -Modules Users,Groups -ExportFormat All` — CSV + JSON + HTML.

`.Invoke-ADAudit.ps1 -Modules GPOs -IncludeGPOReports` — inventaire GPO + rapports XML.

`.Invoke-ADAudit.ps1 -Modules Users,Groups -DomainController dc01.contoso.local` — cibler un DC.

## Prérequis

- Windows PowerShell 5.1 ou PowerShell 7.
- RSAT / module ActiveDirectory.
- GroupPolicy pour les GPO.
- DnsServer pour DNS.
- Droits de lecture suffisants.

## Sécurité

Le framework est **read-only** : il n'utilise pas de cmdlets de création, modification ou suppression AD.

Les exports peuvent contenir des données sensibles. Ne publiez jamais un export réel d'AD dans un dépôt public.

## Roadmap

- Analyse détaillée des paramètres GPO.
- Détection avancée des délégations ACL dangereuses.
- Audit Kerberos approfondi.
- Audit AD CS / PKI.
- DNS avancé.
- Score de sécurité et priorisation.
- Comparaison entre deux audits.
- Rapport HTML interactif.
