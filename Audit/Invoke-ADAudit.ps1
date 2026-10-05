#requires -Version 5.1
[CmdletBinding()]
param(
 [ValidateSet('Interactive','All')][string]$Mode='Interactive',
 [string[]]$Modules,
 [string]$OutputPath=(Join-Path $PWD ('AD-Audit-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))),
 [ValidateSet('JSON','HTML','Both')][string]$ExportFormat='JSON',
 [string]$DomainController,
 [switch]$IncludeGPOReports,[switch]$NoConsole
)
# StrictMode intentionally disabled: the audit must remain compatible with Windows PowerShell 5.1 collections and optional AD attributes.
$ErrorActionPreference='Stop'
$ADParams=@{}; if($DomainController){$ADParams.Server=$DomainController}
$Script:AuditVersion='1.1.0';$Script:StartedAt=Get-Date
$Script:Results=[ordered]@{};$Script:Findings=New-Object System.Collections.Generic.List[object]
$ModuleDefinitions=[ordered]@{
 Users='Comptes utilisateurs';Groups='Groupes et privileges';Computers='Ordinateurs';OUs='Unites organisationnelles';GPOs='GPO et analyse';Domain='Domaine et politiques';DCs='Controleurs de domaine';Sites='Sites et replication';Trusts='Relations de confiance';DNS='DNS';Delegation='Delegations ACL';SPNs='SPN';LAPS='LAPS';Health='Sante AD';Privileged='Privileges';Kerberos='Kerberos';PasswordPolicies='FGPP';Schema='Schema AD';ADCS='AD CS / PKI';RecycleBin='Corbeille AD';AdminSDHolder='AdminSDHolder';GPOAnalysis='Analyse GPO approfondie'
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
 if($p.LockoutThreshold -eq 0){Finding High Domain 'Verrouillage absent' $d.DNSRoot 'LockoutThreshold a 0.' 'Definir une politique de verrouillage adaptee.'}
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
function AuditPrivileged{
 Section 'Audit des privileges';$rows=@();foreach($name in (PrivGroups)){try{$g=Get-ADGroup @ADParams -Identity $name -Properties *;$m=@(Get-ADGroupMember @(ADParams) -Identity $g.DistinguishedName -Recursive -ErrorAction SilentlyContinue);$rows+=[pscustomobject]@{Group=$name;Exists=$true;MemberCount=$m.Count;Members=(($m|select -Expand Name)-join ' | ');DistinguishedName=$g.DistinguishedName};if($m.Count){Finding Medium Privileged ('Groupe privilegie: '+$name) $name ($m.Count.ToString()+' membre(s).') 'Verifier les membres.'}}catch{$rows+=[pscustomobject]@{Group=$name;Exists=$false;MemberCount=0;Members='';DistinguishedName=''}}};$Script:Results.Privileged=$rows;Ok ($rows.Count.ToString()+' groupes sensibles verifies.')
}
function AuditKerberos{
 Section 'Audit Kerberos';$rows=@(Get-ADUser @(ADParams) -Filter * -Properties DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,Enabled,PasswordLastSet|%{if($_.DoesNotRequirePreAuth-or $_.TrustedForDelegation-or $_.TrustedToAuthForDelegation-or @($_.ServicePrincipalName).Count){[pscustomobject]@{Account=$_.SamAccountName;Enabled=$_.Enabled;ASREP=$_.DoesNotRequirePreAuth;UnconstrainedDelegation=$_.TrustedForDelegation;ConstrainedDelegation=$_.TrustedToAuthForDelegation;SPNCount=@($_.ServicePrincipalName).Count;SPNs=(@($_.ServicePrincipalName)-join ' | ');PasswordLastSet=$_.PasswordLastSet;DistinguishedName=$_.DistinguishedName}}});foreach($r in $rows){if($r.ASREP){Finding High Kerberos 'AS-REP roastable account' $r.Account 'Pre-authentification desactivee.' 'Reactiver la pre-authentification.'};if($r.UnconstrainedDelegation){Finding High Kerberos 'Delegation non contrainte' $r.Account 'TrustedForDelegation active.' 'Verifier et supprimer si inutile.'}};$Script:Results.Kerberos=$rows;Ok ($rows.Count.ToString()+' comptes sensibles.')
}
function AuditPasswordPolicies{
 Section 'Audit des politiques de mots de passe';$p=Get-ADDefaultDomainPasswordPolicy @(ADParams);$rows=@([pscustomobject]@{Type='DefaultDomain';Name='Default Domain Policy';MinPasswordLength=$p.MinPasswordLength;PasswordHistoryCount=$p.PasswordHistoryCount;ComplexityEnabled=$p.ComplexityEnabled;MaxPasswordAge=$p.MaxPasswordAge;MinPasswordAge=$p.MinPasswordAge;LockoutThreshold=$p.LockoutThreshold});if(Cmd Get-ADFineGrainedPasswordPolicy){$rows+=@(Get-ADFineGrainedPasswordPolicy @(ADParams) -Filter * -Properties *|%{[pscustomobject]@{Type='FineGrained';Name=$_.Name;Precedence=$_.Precedence;MinPasswordLength=$_.MinPasswordLength;PasswordHistoryCount=$_.PasswordHistoryCount;ComplexityEnabled=$_.ComplexityEnabled;MaxPasswordAge=$_.MaxPasswordAge;LockoutThreshold=$_.LockoutThreshold;AppliesTo=(@($_.AppliesTo)-join ' | ')}})};$Script:Results.PasswordPolicies=$rows;Ok ($rows.Count.ToString()+' politiques.')
}
function AuditSchema{
 Section 'Audit du schema';$s=Get-ADObject @(ADParams) -SearchBase ((Get-ADRootDSE @(ADParams)).schemaNamingContext) -LDAPFilter '(|(objectClass=classSchema)(objectClass=attributeSchema))' -Properties lDAPDisplayName,objectClass,adminDisplayName,whenCreated,whenChanged;$Script:Results.Schema=@($s|%{[pscustomobject]@{LDAPDisplayName=$_.lDAPDisplayName;ObjectClass=($_.objectClass-join ',');AdminDisplayName=$_.adminDisplayName;WhenCreated=$_.whenCreated;WhenChanged=$_.whenChanged;DistinguishedName=$_.DistinguishedName}});Ok ($Script:Results.Schema.Count.ToString()+' objets schema.')
}
function AuditADCS{
 Section 'Audit AD CS';$config=(Get-ADRootDSE @(ADParams)).configurationNamingContext;$rows=@(Get-ADObject @(ADParams) -SearchBase $config -LDAPFilter '(|(objectClass=pKIEnrollmentService)(objectClass=pKICertificateTemplate))' -Properties displayName,cn,certificateTemplates,flags,msPKI-Enrollment-Flag,msPKI-Certificate-Name-Flag,msPKI-Private-Key-Flag|%{[pscustomobject]@{Name=$_.displayName;CN=$_.cn;ObjectClass=($_.objectClass-join ',');CertificateTemplates=(@($_.certificateTemplates)-join ' | ');Flags=$_.flags;EnrollmentFlags=$_.'msPKI-Enrollment-Flag';CertificateNameFlags=$_.'msPKI-Certificate-Name-Flag';PrivateKeyFlags=$_.'msPKI-Private-Key-Flag';DistinguishedName=$_.DistinguishedName}});$Script:Results.ADCS=$rows;if($rows.Count){Finding Info ADCS 'Infrastructure AD CS detectee' 'AD CS' ($rows.Count.ToString()+' objets.') 'Faire une revue PKI dediee.'};Ok ($rows.Count.ToString()+' objets AD CS.')
}
function AuditRecycleBin{
 Section 'Audit de la corbeille AD';$x=@(Get-ADOptionalFeature @(ADParams) -Filter 'Name -eq "Recycle Bin Feature"' -Properties EnabledScopes|%{[pscustomobject]@{Name=$_.Name;Enabled=($_.EnabledScopes.Count -gt 0);EnabledScopes=(@($_.EnabledScopes)-join ' | ');DistinguishedName=$_.DistinguishedName}});$Script:Results.RecycleBin=$x;if($x.Count-and-not $x[0].Enabled){Finding High RecycleBin 'Corbeille AD inactive' 'Recycle Bin Feature' 'La corbeille semble inactive.' 'Verifier la politique de restauration.'};Ok 'Corbeille AD auditee.'
}
function AuditAdminSDHolder{
 Section 'Audit AdminSDHolder';$d=Get-ADDomain @(ADParams);$dn=('CN=AdminSDHolder,CN=System,'+$d.DistinguishedName);$a=Get-Acl ('AD:\'+$dn);$Script:Results.AdminSDHolder=@($a.Access|%{[pscustomobject]@{IdentityReference=$_.IdentityReference;ActiveDirectoryRights=$_.ActiveDirectoryRights;AccessControlType=$_.AccessControlType;ObjectType=$_.ObjectType;IsInherited=$_.IsInherited}});Ok ($Script:Results.AdminSDHolder.Count.ToString()+' ACE.')
}
function AuditGPOAnalysis{
 Section 'Analyse GPO';if(-not(Cmd Get-GPOReport)){Warn 'Get-GPOReport indisponible.';return};$rows=@();foreach($g in @(Get-GPO -All @(ADParams))){try{[xml]$xml=Get-GPOReport -Guid $g.Id -ReportType Xml;$t=$xml.OuterXml;$f=@();if($t-match '(?i)EnableLUA.*false|FilterAdministratorToken.*false'){$f+='UAC weakening'};if($t-match '(?i)fDenyTSConnections.*0|Terminal Services'){$f+='RDP'};if($t-match '(?i)SMB1|LanmanServer.*SMB1'){$f+='SMB legacy'};if($t-match '(?i)DisableRealtimeMonitoring|DisableAntiSpyware'){$f+='Defender'};if($t-match '(?i)SeDebugPrivilege|SeTakeOwnershipPrivilege|SeBackupPrivilege'){$f+='Privileges sensibles'};if($f.Count){Finding Medium GPO ('Configuration sensible: '+$g.DisplayName) $g.DisplayName ($f-join ', ') 'Revoir la configuration.'};$rows+=[pscustomobject]@{Id=$g.Id.Guid;DisplayName=$g.DisplayName;Status=$g.GpoStatus;Flags=($f-join ' | ');Owner=$g.Owner;Created=$g.CreationTime;Modified=$g.ModificationTime}}catch{Warn ('GPO: '+$g.DisplayName+' / '+$_.Exception.Message)}};$Script:Results.GPOAnalysis=$rows;Ok ($rows.Count.ToString()+' GPO analysees.')
}
function GetRiskLevel([int]$score){if($score -ge 75){'Critical'}elseif($score -ge 50){'High'}elseif($score -ge 25){'Medium'}elseif($score -gt 0){'Low'}else{'None'}}
function GetAuditSummary{
 $f=@($Script:Findings);$sum=($f|Measure-Object Score -Sum).Sum;if($null-eq$sum){$sum=0};$score=[Math]::Min(100,[int]$sum)
 $sev=[ordered]@{};foreach($s in @('Critical','High','Medium','Low','Info')){$sev[$s]=@($f|? Severity -eq $s).Count}
 $recs=@($f|? Recommendation|Group-Object Recommendation|Sort-Object Count -Descending|Select-Object -First 10|%{[pscustomobject]@{Recommendation=$_.Name;FindingCount=$_.Count}})
 [pscustomobject]@{RiskScore=$score;RiskLevel=(GetRiskLevel $score);FindingCount=$f.Count;BySeverity=$sev;TopRecommendations=$recs}
}
function ExportResults{
 New-Item -ItemType Directory -Path $OutputPath -Force|Out-Null;$domain=$null;try{$domain=(Get-ADDomain @ADParams).DNSRoot}catch{}
 $summary=GetAuditSummary
 $obj=[ordered]@{Tool='AD Advanced Audit';Version=$Script:AuditVersion;StartedAt=$Script:StartedAt;FinishedAt=Get-Date;Domain=$domain;DomainController=$DomainController;ReadOnly=$true;RiskScore=$summary.RiskScore;RiskLevel=$summary.RiskLevel;Summary=$summary;Modules=@($Script:Results.Keys);Findings=@($Script:Findings);Results=$Script:Results}
 if($ExportFormat-in @('JSON','Both')){$file=Join-Path $OutputPath 'AD-Audit.json';$obj|ConvertTo-Json -Depth 15|Set-Content $file -Encoding UTF8;Ok ('Export JSON: '+$file)}
 if($ExportFormat-in @('HTML','Both')){
  $htmlFile=Join-Path $OutputPath 'AD-Audit.html';$rows=($Script:Findings|Sort-Object @{Expression='Score';Descending=$true}|%{ '<tr><td>'+[System.Net.WebUtility]::HtmlEncode($_.Severity)+'</td><td>'+[System.Net.WebUtility]::HtmlEncode([string]$_.Score)+'</td><td>'+[System.Net.WebUtility]::HtmlEncode($_.Category)+'</td><td>'+[System.Net.WebUtility]::HtmlEncode($_.Title)+'</td><td>'+[System.Net.WebUtility]::HtmlEncode($_.Object)+'</td><td>'+[System.Net.WebUtility]::HtmlEncode($_.Details)+'</td><td>'+[System.Net.WebUtility]::HtmlEncode($_.Recommendation)+'</td></tr>' })-join [Environment]::NewLine
  $css='body{font-family:Segoe UI,Arial;margin:32px;background:#f5f6f8;color:#222}table{width:100%;border-collapse:collapse;background:#fff}th,td{padding:8px;border:1px solid #ddd;text-align:left;vertical-align:top}th{background:#222;color:#fff}.score{font-size:28px;font-weight:bold}'
  $html='<!doctype html><html><head><meta charset="utf-8"><title>AD Advanced Audit</title><style>'+$css+'</style></head><body><h1>AD Advanced Audit</h1><h2>Risk score: '+$summary.RiskScore+'/100 — '+$summary.RiskLevel+'</h2><p>Findings: '+$summary.FindingCount+'</p><table><thead><tr><th>Severity</th><th>Score</th><th>Category</th><th>Title</th><th>Object</th><th>Details</th><th>Recommendation</th></tr></thead><tbody>'+$rows+'</tbody></table></body></html>'
  Set-Content -Path $htmlFile -Value $html -Encoding UTF8;Ok ('Export HTML: '+$htmlFile)
 }
}function SelectModules{
 Section 'Selection des modules';$k=@($ModuleDefinitions.Keys);for($i=0;$i-lt $k.Count;$i++){W(('[{0,2}] {1,-12} {2}'-f($i+1),$k[$i],$ModuleDefinitions[$k[$i]]))};W '[A] Tout auditer';$a=Read-Host 'Selection (ex: 1,2,5 ou A)';if($a-match '^[Aa]$'){return $k};$r=@();foreach($p in($a-split ',')){$n=0;if([int]::TryParse($p.Trim(),[ref]$n)-and$n-ge 1-and$n-le$k.Count){$r+=$k[$n-1]}};@($r|select -Unique)
}
function Run([string]$n){switch($n){Users{AuditUsers};Groups{AuditGroups};Computers{AuditComputers};OUs{AuditOUs};GPOs{AuditGPOs};Domain{AuditDomain};DCs{AuditDCs};Sites{AuditSites};Trusts{AuditTrusts};DNS{AuditDNS};Delegation{AuditDelegation};SPNs{AuditSPNs};LAPS{AuditLAPS};Health{AuditHealth};Privileged{AuditPrivileged};Kerberos{AuditKerberos};PasswordPolicies{AuditPasswordPolicies};Schema{AuditSchema};ADCS{AuditADCS};RecycleBin{AuditRecycleBin};AdminSDHolder{AuditAdminSDHolder};GPOAnalysis{AuditGPOAnalysis};default{Warn ('Module inconnu: '+$n)}}}
Section ('AD Advanced Audit v'+$Script:AuditVersion)
if(-not(Cmd Get-ADDomain)){throw 'Le module ActiveDirectory est requis (RSAT).'}
$Modules = @($Modules)
if(@($Modules).Count -eq 0){if($Mode -eq 'All'){$Modules=@($ModuleDefinitions.Keys)}else{$Modules=@(SelectModules)}}
if(@($Modules).Count -eq 0){throw 'Aucun module selectionne.'};New-Item -ItemType Directory -Path $OutputPath -Force|Out-Null
foreach($m in $Modules){try{Run $m}catch{Warn ('Module '+$m+' en erreur: '+$_.Exception.Message);Finding High Engine ('Echec du module '+$m) $m $_.Exception.Message 'Verifier les droits, RSAT et la connectivite.'}}
ExportResults;Section 'Fin de l audit';W ('Modules: '+($Script:Results.Keys-join ', '));W ('Findings: '+$Script:Findings.Count);$s=GetAuditSummary;W ('Risk score: '+$s.RiskScore+'/100 ('+$s.RiskLevel+')');W ('Repertoire: '+$OutputPath)
