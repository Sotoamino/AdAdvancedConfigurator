#requires -Version 5.1
[CmdletBinding()]
param(
 [ValidateSet('Interactive','All')][string]$Mode='Interactive',
 [string[]]$Modules,
 [string]$OutputPath=(Join-Path $PWD ('AD-Audit-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))),
 [ValidateSet('CSV','JSON','HTML','All')][string]$ExportFormat='All',
 [string]$DomainController,
 [switch]$IncludeGPOReports,[switch]$NoConsole
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ADParams=ADParams
$Script:AuditVersion='1.0.0';$Script:StartedAt=Get-Date
$Script:Results=[ordered]@{};$Script:Findings=New-Object System.Collections.Generic.List[object]
$ModuleDefinitions=[ordered]@{
 Users='Comptes utilisateurs';Groups='Groupes et privileges';Computers='Ordinateurs';OUs='Unites organisationnelles'
 GPOs='GPO';Domain='Domaine et politique de mots de passe';DCs='Controleurs de domaine'
 Sites='Sites, subnets et liens';Trusts='Relations de confiance';DNS='DNS'
 Delegation='Delegations ACL';SPNs='SPN';LAPS='LAPS';Health='Sante de replication'
}
function W([string]$s){if(-not $NoConsole){Write-Host $s}}
function Section([string]$s){W '';W ('='*78);W ('  '+$s);W ('='*78)}
function Ok([string]$s){W ('[+] '+$s)}
function Warn([string]$s){if(-not $NoConsole){Write-Host ('[!] '+$s) -ForegroundColor Yellow}}
function Cmd([string]$n){return [bool](Get-Command $n -ErrorAction SilentlyContinue)}
function ADParams{$p=@{};if($DomainController){$p.Server=$DomainController};$p}
function Finding{param([string]$Severity,[string]$Category,[string]$Title,[string]$Object,[string]$Details,[string]$Recommendation)
 $Script:Findings.Add([pscustomobject]@{Severity=$Severity;Category=$Category;Title=$Title;Object=$Object;Details=$Details;Recommendation=$Recommendation})}
function PrivGroups{@('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Server Operators','Backup Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Key Admins','Enterprise Key Admins','Protected Users','Cert Publishers')}
function AccountType([int]$u){
 $f=@();if($u-band 2){$f+='ACCOUNTDISABLE'};if($u-band 32){$f+='PASSWD_NOTREQD'};if($u-band 512){$f+='NORMAL_ACCOUNT'}
 if($u-band 4096){$f+='INTERDOMAIN_TRUST_ACCOUNT'};if($u-band 8192){$f+='WORKSTATION_TRUST_ACCOUNT'};if($u-band 16384){$f+='SERVER_TRUST_ACCOUNT'}
 if($u-band 524288){$f+='TRUSTED_FOR_DELEGATION'};if($u-band 1048576){$f+='NOT_DELEGATED'};if($u-band 4194304){$f+='DONT_REQ_PREAUTH'}
 if($u-band 8388608){$f+='PASSWORD_EXPIRED'};if($u-band 16777216){$f+='TRUSTED_TO_AUTH_FOR_DELEGATION'};($f -join ',')
}
function Recurse([string]$dn){try{@(Get-ADGroupMember @ADParams -Identity $dn -Recursive -ErrorAction Stop)}catch{Warn ('Membres recursifs indisponibles: '+$dn+' / '+$_.Exception.Message);@()}}
function AuditUsers{
 Section 'Audit des utilisateurs';$priv=PrivGroups
 $x=@(Get-ADUser @ADParams -Filter * -Properties *|%{
  $g=@(Get-ADPrincipalGroupMembership @ADParams -Identity $_.DistinguishedName -ErrorAction SilentlyContinue);$gn=@($g|select -Expand Name);$pg=@($g|?{$priv-contains $_.Name})
  if($_.PasswordNeverExpires){Finding Medium Users 'Mot de passe permanent' $_.SamAccountName 'PasswordNeverExpires active.' 'Desactiver sauf exception documentee.'}
  if($_.PasswordNotRequired){Finding High Users 'Mot de passe non requis' $_.SamAccountName 'PASSWD_NOTREQD active.' 'Imposer un mot de passe et verifier le compte.'}
  if($_.DoesNotRequirePreAuth){Finding High Users 'Pre-authentification Kerberos desactivee' $_.SamAccountName 'Compte AS-REP roastable.' 'Reactiver la pre-authentification.'}
  if($_.TrustedForDelegation){Finding High Users 'Delegation Kerberos non contrainte' $_.SamAccountName 'TrustedForDelegation active.' 'Verifier et limiter la delegation.'}
  [pscustomobject]@{
   SamAccountName=$_.SamAccountName;UserPrincipalName=$_.UserPrincipalName;Name=$_.Name;GivenName=$_.GivenName;Surname=$_.Surname;DisplayName=$_.DisplayName
   Enabled=$_.Enabled;AccountType=(AccountType $_.UserAccountControl);UserAccountControl=$_.UserAccountControl;DistinguishedName=$_.DistinguishedName;CanonicalName=$_.CanonicalName
   Description=$_.Description;Department=$_.Department;Title=$_.Title;Company=$_.Company;EmailAddress=$_.Mail;EmployeeId=$_.EmployeeID
   Created=$_.Created;Modified=$_.Modified;LastLogonDate=$_.LastLogonDate;LastLogonTimestamp=$_.LastLogonTimestamp;LastBadPasswordAttempt=$_.LastBadPasswordAttempt
   BadLogonCount=$_.BadLogonCount;BadPwdCount=$_.BadPwdCount;LockedOut=$_.LockedOut;PasswordLastSet=$_.PasswordLastSet;PasswordExpired=$_.PasswordExpired
   PasswordNeverExpires=$_.PasswordNeverExpires;PasswordNotRequired=$_.PasswordNotRequired;CannotChangePassword=$_.CannotChangePassword;AccountExpirationDate=$_.AccountExpirationDate
   SmartcardLogonRequired=$_.SmartcardLogonRequired;DoesNotRequirePreAuth=$_.DoesNotRequirePreAuth;TrustedForDelegation=$_.TrustedForDelegation
   TrustedToAuthForDelegation=$_.TrustedToAuthForDelegation;Groups=($gn-join ' | ');PrivilegedGroups=(($pg|select -Expand Name)-join ' | ');IsPrivileged=($pg.Count-gt 0)
   ServicePrincipalNames=(@($_.ServicePrincipalNames)-join ' | ');SID=$_.SID.Value
  }
 });$Script:Results.Users=$x;Ok ($x.Count.ToString()+' utilisateurs audites.')
}
function AuditGroups{
 Section 'Audit des groupes';$priv=PrivGroups
 $x=@(Get-ADGroup @ADParams -Filter * -Properties *|%{
  $d=@(Get-ADGroupMember @ADParams -Identity $_.DistinguishedName -ErrorAction SilentlyContinue);$r=@(Recurse $_.DistinguishedName)
  [pscustomobject]@{Name=$_.Name;SamAccountName=$_.SamAccountName;GroupScope=$_.GroupScope;GroupCategory=$_.GroupCategory;DistinguishedName=$_.DistinguishedName;Description=$_.Description;Created=$_.Created;Modified=$_.Modified;ManagedBy=$_.ManagedBy;DirectMemberCount=$d.Count;RecursiveMemberCount=$r.Count;DirectMembers=(($d|select -Expand Name)-join ' | ');RecursiveMembers=(($r|select -Expand Name)-join ' | ');IsPrivileged=($priv-contains $_.Name);SID=$_.SID.Value}
 });$Script:Results.Groups=$x;Ok ($x.Count.ToString()+' groupes audites.')
}
function AuditComputers{
 Section 'Audit des ordinateurs'
 $x=@(Get-ADComputer @ADParams -Filter * -Properties *|%{
  $stale=($_.LastLogonDate -and $_.LastLogonDate-lt (Get-Date).AddDays(-90))
  if($stale-and $_.Enabled){Finding Medium Computers 'Ordinateur inactif > 90 jours' $_.Name ('Derniere connexion: '+$_.LastLogonDate) 'Desactiver puis traiter selon la procedure de parc.'}
  [pscustomobject]@{Name=$_.Name;DNSHostName=$_.DNSHostName;Enabled=$_.Enabled;OperatingSystem=$_.OperatingSystem;OperatingSystemVersion=$_.OperatingSystemVersion;DistinguishedName=$_.DistinguishedName;CanonicalName=$_.CanonicalName;Created=$_.Created;Modified=$_.Modified;LastLogonDate=$_.LastLogonDate;LastLogonTimestamp=$_.LastLogonTimestamp;PasswordLastSet=$_.PasswordLastSet;TrustedForDelegation=$_.TrustedForDelegation;TrustedToAuthForDelegation=$_.TrustedToAuthForDelegation;ServicePrincipalNames=(@($_.ServicePrincipalName)-join ' | ');SID=$_.SID.Value;Stale90Days=$stale}
 });$Script:Results.Computers=$x;Ok ($x.Count.ToString()+' ordinateurs audites.')
}
function AuditOUs{
 Section 'Audit des OU';$x=@(Get-ADOrganizationalUnit @ADParams -Filter * -Properties *|%{[pscustomobject]@{Name=$_.Name;DistinguishedName=$_.DistinguishedName;CanonicalName=$_.CanonicalName;Description=$_.Description;ProtectedFromAccidentalDeletion=$_.ProtectedFromAccidentalDeletion;Created=$_.Created;Modified=$_.Modified;LinkedGroupPolicyObjects=(@($_.LinkedGroupPolicyObjects)-join ' | ')}})
 $Script:Results.OUs=$x;Ok ($x.Count.ToString()+' OU auditees.')
}
function AuditGPOs{
 Section 'Audit des GPO';if(-not(Cmd Get-GPO)){Warn 'Module GroupPolicy absent. GPO ignorees.';return}
 $x=@(Get-GPO -All @ADParams|%{
  $rp=$null;if($IncludeGPOReports){try{$rp=Join-Path $OutputPath ('GPO-'+$_.Id.Guid+'.xml');Get-GPOReport -Guid $_.Id -ReportType Xml -Path $rp -ErrorAction Stop}catch{Warn ('Rapport GPO impossible: '+$_.DisplayName+' / '+$_.Exception.Message)}}
  [pscustomobject]@{Id=$_.Id.Guid;DisplayName=$_.DisplayName;DomainName=$_.DomainName;Owner=$_.Owner;GpoStatus=$_.GpoStatus;Description=$_.Description;CreationTime=$_.CreationTime;ModificationTime=$_.ModificationTime;WmiFilter=$_.WmiFilter.Name;ReportXml=$rp}
 });$Script:Results.GPOs=$x;Ok ($x.Count.ToString()+' GPO auditees.')
}
function AuditDomain{
 Section 'Audit du domaine';$d=Get-ADDomain @ADParams;$f=Get-ADForest @ADParams;$p=Get-ADDefaultDomainPasswordPolicy @ADParams
 if($p.MinPasswordLength-lt 12){Finding Medium Domain 'Longueur de mot de passe faible' $d.DNSRoot ('Minimum: '+$p.MinPasswordLength) 'Viser 12 caracteres ou davantage.'}
 if($p.PasswordHistoryCount-lt 10){Finding Low Domain 'Historique de mot de passe faible' $d.DNSRoot ('Historique: '+$p.PasswordHistoryCount) 'Augmenter l historique.'}
 if($p.LockoutThreshold-eq 0){Finding High Domain 'Verrouillage absent' $d.DNSRoot 'LockoutThreshold a 0.' 'Definir une politique de verrouillage adaptee.'}
 $Script:Results.Domain=@([pscustomobject]@{DNSRoot=$d.DNSRoot;NetBIOSName=$d.NetBIOSName;DomainMode=$d.DomainMode;ForestRoot=$f.RootDomain;ForestMode=$f.ForestMode;DomainControllers=($d.ReplicaDirectoryServers-join ' | ');MinPasswordLength=$p.MinPasswordLength;PasswordHistoryCount=$p.PasswordHistoryCount;ComplexityEnabled=$p.ComplexityEnabled;ReversibleEncryptionEnabled=$p.ReversibleEncryptionEnabled;MaxPasswordAge=$p.MaxPasswordAge;MinPasswordAge=$p.MinPasswordAge;LockoutThreshold=$p.LockoutThreshold;LockoutDuration=$p.LockoutDuration;LockoutObservationWindow=$p.LockoutObservationWindow})
 Ok 'Domaine, foret et politique de mots de passe audites.'
}
function AuditDCs{
 Section 'Audit des controleurs de domaine';$x=@(Get-ADDomainController -Filter * @ADParams|%{[pscustomobject]@{HostName=$_.HostName;IPv4Address=$_.IPv4Address;Site=$_.Site;IsGlobalCatalog=$_.IsGlobalCatalog;IsReadOnly=$_.IsReadOnly;OperatingSystem=$_.OperatingSystem;OperatingSystemVersion=$_.OperatingSystemVersion;Forest=$_.Forest;Domain=$_.Domain;ComputerObjectDN=$_.ComputerObjectDN;NTDSSettingsObjectDN=$_.NTDSSettingsObjectDN;InvocationId=$_.InvocationId}})
 $Script:Results.DCs=$x;Ok ($x.Count.ToString()+' DC audites.')
}
function AuditSites{
 Section 'Audit des sites AD';$s=@(Get-ADReplicationSite @ADParams -Filter *);$n=@(Get-ADReplicationSubnet @ADParams -Filter *);$l=@(Get-ADReplicationSiteLink @ADParams -Filter *)
 $Script:Results.Sites=@($s|%{[pscustomobject]@{Name=$_.Name;DistinguishedName=$_.DistinguishedName;Description=$_.Description}})
 $Script:Results.Subnets=@($n|%{[pscustomobject]@{Name=$_.Name;Site=$_.Site;Location=$_.Location;Description=$_.Description}})
 $Script:Results.SiteLinks=@($l|%{[pscustomobject]@{Name=$_.Name;SitesIncluded=($_.SitesIncluded-join ' | ');Cost=$_.Cost;ReplicationFrequencyInMinutes=$_.ReplicationFrequencyInMinutes}})
 Ok ($s.Count.ToString()+' sites, '+$n.Count+' subnets, '+$l.Count+' liens.')
}
function AuditTrusts{
 Section 'Audit des relations de confiance';$x=@(Get-ADTrust @ADParams -Filter *|%{[pscustomobject]@{Name=$_.Name;Direction=$_.Direction;TrustType=$_.TrustType;TrustAttributes=$_.TrustAttributes;SelectiveAuthentication=$_.SelectiveAuthentication;SIDFilteringForestAware=$_.SIDFilteringForestAware;SIDFilteringQuarantined=$_.SIDFilteringQuarantined;Source=$_.Source;Target=$_.Target}})
 $Script:Results.Trusts=$x;Ok ($x.Count.ToString()+' trust(s) audite(s).')
}
function AuditSPNs{
 Section 'Audit des SPN';$x=@(Get-ADUser @ADParams -Filter * -Properties ServicePrincipalName,Enabled|%{foreach($spn in @($_.ServicePrincipalName)){[pscustomobject]@{Account=$_.SamAccountName;Enabled=$_.Enabled;SPN=$spn;DistinguishedName=$_.DistinguishedName}}})
 $Script:Results.SPNs=$x;Ok ($x.Count.ToString()+' SPN utilisateur(s).')
}
function AuditLAPS{
 Section 'Audit LAPS';$x=@(Get-ADComputer @ADParams -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'|%{[pscustomobject]@{Computer=$_.Name;LegacyLAPSAttributePresent=($null-ne $_.'ms-Mcs-AdmPwdExpirationTime');LegacyLAPSExpiration=$_.'ms-Mcs-AdmPwdExpirationTime';WindowsLAPSAttributePresent=($null-ne $_.'msLAPS-PasswordExpirationTime');WindowsLAPSExpiration=$_.'msLAPS-PasswordExpirationTime';DistinguishedName=$_.DistinguishedName}})
 $Script:Results.LAPS=$x;$none=@($x|?{-not $_.LegacyLAPSAttributePresent-and-not $_.WindowsLAPSAttributePresent});if($none.Count-gt 0){Finding Medium LAPS 'Ordinateurs sans trace LAPS' 'AD Computers' ($none.Count.ToString()+' ordinateur(s).') 'Verifier la couverture Windows LAPS.'};Ok ($x.Count.ToString()+' ordinateurs verifies pour LAPS.')
}
function AuditDelegation{
 Section 'Audit des delegations ACL';$root=(Get-ADRootDSE @ADParams).defaultNamingContext
 $x=@(Get-Acl ('AD:\'+$root)|select -Expand Access|%{[pscustomobject]@{IdentityReference=$_.IdentityReference;ActiveDirectoryRights=$_.ActiveDirectoryRights;AccessControlType=$_.AccessControlType;ObjectType=$_.ObjectType;InheritanceType=$_.InheritanceType;IsInherited=$_.IsInherited}})
 $Script:Results.Delegation=$x;Ok ($x.Count.ToString()+' ACE collectees.')
}
function AuditDNS{
 Section 'Audit DNS';$x=@();if(Cmd Get-DnsServerZone){try{$x=@(Get-DnsServerZone -ComputerName $DomainController -ErrorAction Stop|select ZoneName,ZoneType,IsDsIntegrated,DynamicUpdate,ReplicationScope,DirectoryPartitionName)}catch{Warn ('DNS indisponible: '+$_.Exception.Message)}}else{Warn 'Module DnsServer absent. DNS ignore.'};$Script:Results.DNS=$x;Ok ($x.Count.ToString()+' zone(s) DNS.')
}
function AuditHealth{
 Section 'Audit de la sante AD';$x=@();if(Cmd Get-ADReplicationPartnerMetadata){try{$x=@(Get-ADDomainController -Filter * @ADParams|%{Get-ADReplicationPartnerMetadata -Target $_.HostName -Scope Server -ErrorAction SilentlyContinue|select Server,Partner,LastReplicationSuccess,LastReplicationResult,ConsecutiveReplicationFailures,LastReplicationAttempt});foreach($z in $x){if($z.ConsecutiveReplicationFailures-gt 0-or $z.LastReplicationResult-ne 0){Finding High Health 'Echec de replication AD' (($z.Server)+' -> '+($z.Partner)) ('Resultat='+$z.LastReplicationResult+'; echecs='+$z.ConsecutiveReplicationFailures) 'Analyser DNS, RPC, Kerberos et les journaux AD.'}}}catch{Warn ('Replication indisponible: '+$_.Exception.Message)}};$Script:Results.Health=$x;Ok ($x.Count.ToString()+' relations de replication.')
}
function ExportResults{
 Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue;New-Item -ItemType Directory -Path $OutputPath -Force|Out-Null
 foreach($n in $Script:Results.Keys){$d=@($Script:Results[$n]);if($d.Count-eq 0){continue};if($ExportFormat-in @('CSV','All')){$d|Export-Csv (Join-Path $OutputPath ($n+'.csv')) -NoTypeInformation -Encoding UTF8 -Delimiter ';'};if($ExportFormat-in @('JSON','All')){$d|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputPath ($n+'.json')) -Encoding UTF8}}
 if($Script:Findings.Count-gt 0){if($ExportFormat-in @('CSV','All')){$Script:Findings|Export-Csv (Join-Path $OutputPath 'Findings.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'};if($ExportFormat-in @('JSON','All')){$Script:Findings|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputPath 'Findings.json') -Encoding UTF8}}
 $sum=[pscustomobject]@{ToolVersion=$Script:AuditVersion;StartedAt=$Script:StartedAt;FinishedAt=Get-Date;DomainController=$DomainController;Modules=($Script:Results.Keys-join ', ');FindingCount=$Script:Findings.Count;Critical=@($Script:Findings|? Severity-eq Critical).Count;High=@($Script:Findings|? Severity-eq High).Count;Medium=@($Script:Findings|? Severity-eq Medium).Count;Low=@($Script:Findings|? Severity-eq Low).Count}
 $sum|ConvertTo-Json|Set-Content (Join-Path $OutputPath 'Summary.json') -Encoding UTF8
 if($ExportFormat-in @('HTML','All')){
  $fh=($Script:Findings|ConvertTo-Html -Fragment -PreContent '<h2>Findings</h2>')-join [Environment]::NewLine
  $ss=foreach($n in $Script:Results.Keys){$d=@($Script:Results[$n]);if($d.Count-gt 0){'<h2>'+[System.Web.HttpUtility]::HtmlEncode($n)+'</h2>'+(($d|select -First 500|ConvertTo-Html -Fragment)-join [Environment]::NewLine)}}
  $html='<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>AD Audit</title><style>body{font-family:Segoe UI,Arial;margin:30px;background:#f5f7fa}table{border-collapse:collapse;width:100%;background:white;font-size:12px}th,td{border:1px solid #ddd;padding:6px;text-align:left}th{background:#e9eef3}</style></head><body><h1>Active Directory Audit</h1><p>DC: '+$DomainController+'</p><p>Findings: '+$Script:Findings.Count+'</p>'+$fh+($ss-join [Environment]::NewLine)+'</body></html>'
  $html|Set-Content (Join-Path $OutputPath 'AD-Audit.html') -Encoding UTF8
 };Ok ('Exports: '+$OutputPath)
}
function SelectModules{
 Section 'Selection des modules';$k=@($ModuleDefinitions.Keys);for($i=0;$i-lt $k.Count;$i++){W(('[{0,2}] {1,-12} {2}'-f($i+1),$k[$i],$ModuleDefinitions[$k[$i]]))};W '[A] Tout auditer';$a=Read-Host 'Selection (ex: 1,2,5 ou A)';if($a-match '^[Aa]$'){return $k};$r=@();foreach($p in($a-split ',')){$n=0;if([int]::TryParse($p.Trim(),[ref]$n)-and$n-ge 1-and$n-le$k.Count){$r+=$k[$n-1]}};@($r|select -Unique)
}
function Run([string]$n){switch($n){Users{AuditUsers};Groups{AuditGroups};Computers{AuditComputers};OUs{AuditOUs};GPOs{AuditGPOs};Domain{AuditDomain};DCs{AuditDCs};Sites{AuditSites};Trusts{AuditTrusts};DNS{AuditDNS};Delegation{AuditDelegation};SPNs{AuditSPNs};LAPS{AuditLAPS};Health{AuditHealth};default{Warn ('Module inconnu: '+$n)}}}
Section ('AD Advanced Audit v'+$Script:AuditVersion)
if(-not(Cmd Get-ADDomain)){throw 'Le module ActiveDirectory est requis (RSAT).'}
if(-not$Modules-or$Modules.Count-eq 0){ }else{if($Mode-eq 'All'){$Modules=@($ModuleDefinitions.Keys)}else{$Modules=SelectModules}}
if($Modules.Count-eq 0){throw 'Aucun module selectionne.'};New-Item -ItemType Directory -Path $OutputPath -Force|Out-Null
foreach($m in $Modules){try{Run $m}catch{Warn ('Module '+$m+' en erreur: '+$_.Exception.Message);Finding High Engine ('Echec du module '+$m) $m $_.Exception.Message 'Verifier les droits, RSAT et la connectivite.'}}
ExportResults;Section 'Fin de l audit';W ('Modules: '+($Script:Results.Keys-join ', '));W ('Findings: '+$Script:Findings.Count);W ('Repertoire: '+$OutputPath)
