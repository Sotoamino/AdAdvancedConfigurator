# AD Advanced Audit

Framework PowerShell d'audit et d'analyse approfondie d'Active Directory. Version actuelle : **1.4.0**.

## Garantie

Le script est conçu en **lecture seule** : aucune création, modification ou suppression d'objet AD, GPO, DNS, ACL, compte ou groupe. Les seules écritures locales sont les fichiers d'export explicitement demandés (`AD-Audit.json`, `AD-Audit.html`, ou les deux). Aucun fichier GPO intermédiaire n'est créé.

## Modules

### Inventaire

- Users — **tous les comptes utilisateurs du domaine**, attributs AD renseignés, état Enabled vérifié par UAC, UAC brut et décodé, état calculé du verrouillage et du mot de passe, dernier logon exact recherché sur les DC, dernier logon répliqué, groupes directs/recursifs, privilèges, Kerberos, délégation, SPN, GPO liées et snapshot des attributs AD.
- Groups — groupes, portée, type, membres directs/recursifs et groupes privilégiés.
- Computers — OS, connexions, inactivité, delegation et SPN.
- OUs — OU, protection contre suppression accidentelle et GPO liées.
- GPOs — inventaire GPO et état.
- Domain — domaine/forêt et politique de mots de passe.
- DCs — contrôleurs de domaine.
- Sites — sites, subnets et liens.
- Trusts — relations de confiance.
- DNS — zones DNS.
- Schema — objets du schema AD.
- Security — collecte transversale dédiée à l'audit sécurité : marqueurs AdminCount, SPN, délégation, RBCD, SIDHistory, identités alternatives, clés de credential, certificats utilisateurs, types de chiffrement Kerberos, MachineAccountQuota et groupes sensibles.

### Analyse sécurité

- Privileged — groupes sensibles et membres récursifs.
- Kerberos — AS-REP roastable, delegation non contrainte, comptes portant des SPN.
- PasswordPolicies — politique de domaine et FGPP.
- LAPS — couverture Legacy LAPS / Windows LAPS.
- AdminSDHolder — ACL du conteneur de protection des comptes privilégiés.
- Delegation — ACL de la racine du domaine.
- ADCS — détection des objets AD CS / templates.
- RecycleBin — état de la corbeille AD.
- Health — réplication AD.
- GPOAnalysis — analyse de plusieurs paramètres sensibles dans les rapports GPO.

## Utilisation

Mode interactif :

    .\Invoke-ADAudit.ps1

Tout auditer :

    .\Invoke-ADAudit.ps1 -Mode All

Sélection directe :

    .\Invoke-ADAudit.ps1 -Modules Users,Groups,Kerberos,GPOAnalysis,Health

Cibler un DC :

    .\Invoke-ADAudit.ps1 -Modules Users,Groups,Health -DomainController dc01.example.local

Export HTML :

    .\Invoke-ADAudit.ps1 -Mode All -ExportFormat HTML

Export JSON + HTML :

    .\Invoke-ADAudit.ps1 -Mode All -ExportFormat Both

## Export et performances

L'export est conçu pour rester compatible avec Windows PowerShell 5.1 et PowerShell 7, tout en limitant le travail inutile :

- les données sont normalisées une seule fois avant la sérialisation JSON ;
- les exports JSON et HTML réutilisent la même représentation JSON ;
- le JSON est généré en mode compact (-Compress) pour réduire la taille et le temps d'écriture ;
- l'export affiche sa progression et son temps total lorsque la console est active ;
- la taille du fichier final est affichée après écriture ;
- aucun fichier intermédiaire de sérialisation n'est créé ;
- l'encodage UTF-8 est écrit sans BOM ;
- les attributs binaires AD du snapshot brut sont encodés en Base64 au lieu d'être développés octet par octet ;
- les résultats AD restent en lecture seule.

Le Viewer n'a pas besoin d'un JSON indenté : il charge directement le JSON compact produit par l'auditeur.

## Viewer HTML

Un visualiseur local est disponible dans :

    Audit\Viewer\index.html

Il permet de charger directement `AD-Audit.json` et d'afficher :

- un tableau de bord synthétique ;
- la liste des modules et le nombre d'objets collectés ;
- des tableaux avec recherche et pagination ;
- le détail complet d'un objet ;
- le JSON brut d'un objet ;
- les findings remontés par l'audit.

Le viewer est **100 % local** : aucun CDN, aucune API distante et aucune donnée n'est envoyée à un service externe.

Pour l'utiliser, ouvrir `Audit\Viewer\index.html` puis cliquer sur **Charger un JSON** et sélectionner le rapport.

## Findings

Les anomalies sont centralisées dans `Findings` avec Severity, Category, Title, Object, Details et Recommendation.

Les niveaux de sévérité sont actuellement utilisés comme indicateurs d'audit. **Le scoring global est volontairement désactivé pour le moment.**

Les findings doivent toujours être validés avec le contexte réel de l'environnement.

## Prérequis

- Windows PowerShell 5.1 ou PowerShell 7.
- RSAT Active Directory / module ActiveDirectory.
- GroupPolicy pour les GPO.
- DnsServer pour DNS.
- Droits de lecture suffisants.

## Données sensibles

Un audit AD peut contenir des noms, UPN, groupes privilégiés, structure OU, SPN, configuration de sécurité et informations PKI. Ne publiez jamais un export issu d'une infrastructure réelle dans un dépôt public.

## Évolutions

- analyse complète des paramètres GPO ;
- analyse ACL avancée avec chemins d'escalade ;
- analyse des comptes de service ;
- audit Kerberos approfondi ;
- audit AD CS complet ;
- analyse DNS avancée ;
- scoring RSSI ;
- comparaison de deux audits ;
- contrôles CIS / ANSSI avec evidence ;
- chemins d'administration tiering ;
- permissions dangereuses sur objets AD.

### Garantie de non-modification

Le moteur d'audit utilise uniquement des opérations de lecture sur l'AD, la forêt, les GPO, les ACL, DNS et les objets de configuration. Il ne crée, modifie, supprime, désactive ou réinitialise aucun objet AD.

La seule écriture locale effectuée par le script correspond aux fichiers de rapport demandés dans `-OutputPath`. Aucun module, service, tâche planifiée, variable système ou configuration Windows n'est installé ou modifié.


## Analyse et scoring

Le scoring est réalisé exclusivement dans le Viewer, à partir du JSON produit par l'audit.

- Le collecteur PowerShell reste en lecture seule.
- Aucun score n'est écrit dans Active Directory.
- Le JSON source n'est pas modifié par le Viewer.
- Le score global est accompagné d'un niveau de couverture.
- Les scores sont détaillés par domaine.
- Chaque pénalité affiche la règle, l'objet concerné, les données ayant déclenché la règle et une recommandation.
- Les pénalités sont plafonnées par domaine afin d'éviter qu'un grand nombre d'objets similaires ne domine artificiellement le score.
- L'absence d'un module audité n'est pas considérée comme une conformité : elle réduit la couverture de l'analyse.

Le scoring est une analyse heuristique destinée à aider la revue humaine. Il ne constitue ni une certification, ni un équivalent d'un audit RSoP/GPO complet ou d'une analyse d'escalade de privilèges.
