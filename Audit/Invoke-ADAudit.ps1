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
$Script:AuditVersion='1.2.0';$Script:StartedAt=Get-Date
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
 [void]$Script:Findings.Add([pscustomobject]@{Severity=$Severity;Category=$Category;Title=$Title;Object=$Object;Details=$Details;Recommendation=$Recommendation})
}
function PrivGroups{@('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Server Operators','Backup Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Key Admins','Enterprise Key Admins','Protected Users','Cert Publishers')}
function AccountType([int64]$u){
 $f=New-Object System.Collections.Generic.List[string]
 $map=@(
  @{Bit=1;Name='SCRIPT'},@{Bit=2;Name='ACCOUNTDISABLE'},@{Bit=8;Name='HOMEDIR_REQUIRED'},@{Bit=16;Name='LOCKOUT'},
  @{Bit=32;Name='PASSWD_NOTREQD'},@{Bit=64;Name='PASSWD_CANT_CHANGE'},@{Bit=128;Name='ENCRYPTED_TEXT_PASSWORD_ALLOWED'},
  @{Bit=256;Name='TEMP_DUPLICATE_ACCOUNT'},@{Bit=512;Name='NORMAL_ACCOUNT'},@{Bit=2048;Name='INTERDOMAIN_TRUST_ACCOUNT'},
  @{Bit=4096;Name='WORKSTATION_TRUST_ACCOUNT'},@{Bit=8192;Name='SERVER_TRUST_ACCOUNT'},@{Bit=65536;Name='DONT_EXPIRE_PASSWORD'},
  @{Bit=131072;Name='MNS_LOGON_ACCOUNT'},@{Bit=262144;Name='SMARTCARD_REQUIRED'},@{Bit=524288;Name='TRUSTED_FOR_DELEGATION'},
  @{Bit=1048576;Name='NOT_DELEGATED'},@{Bit=2097152;Name='USE_DES_KEY_ONLY'},@{Bit=4194304;Name='DONT_REQ_PREAUTH'},
  @{Bit=8388608;Name='PASSWORD_EXPIRED'},@{Bit=16777216;Name='TRUSTED_TO_AUTH_FOR_DELEGATION'},@{Bit=67108864;Name='PARTIAL_SECRETS_ACCOUNT'}
 )
 foreach($item in $map){if(($u -band [int64]$item.Bit) -ne 0){[void]$f.Add($item.Name)}}
 $f -join ','
}
function Recurse([string]$dn){try{@(Get-ADGroupMember @ADParams -Identity $dn -Recursive -ErrorAction Stop)}catch{Warn ('Membres recursifs indisponibles: '+$dn+' / '+$_.Exception.Message);@()}}
function Get-UserLinkedGPOs([string]$UserDN){
 $result=New-Object System.Collections.Generic.List[string]
 if(-not(Cmd Get-GPInheritance)){return @()}
 $parts=$UserDN -split ','
 $ous=New-Object System.Collections.Generic.List[string]
 $dcParts=@($parts|Where-Object {$_ -like 'DC=*'})
 $ouParts=@($parts|Where-Object {$_ -like 'OU=*'})
 for($i=0;$i -lt $ouParts.Count;$i++){
  $dn=($ouParts[$i..($ouParts.Count-1)] + $dcParts) -join ','
  [void]$ous.Add($dn)
 }
 foreach($ou in $ous){
  try{
   $inheritance=Get-GPInheritance -Target $ou -ErrorAction Stop
   foreach($link in @($inheritance.GpoLinks)){
    if($link.GpoId){[void]$result.Add(([string]$link.DisplayName)+' ['+([string]$link.GpoId)+']')}
   }
  }catch{}
 }
 return @($result|Select-Object -Unique)
}

function Get-ADUserRawAttributes($User){
 $raw=[ordered]@{}
 foreach($p in $User.PSObject.Properties){
  try{
   $v=$p.Value
   if($null -eq $v){continue}
   if($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])){
    $items=@($v|ForEach-Object {[string]$_})
    if($items.Count -gt 0){$raw[$p.Name]=$items}
   }else{
    $raw[$p.Name]=$v
   }
  }catch{}
 }
 $raw
}

function Get-UserLastLogonAccurate([string]$UserDN,[object[]]$DomainControllers){
 $bestDate=$null;$bestDC=$null;$bestRaw=0
 foreach($dc in @($DomainControllers)){
  try{
   $u=Get-ADUser -Server $dc -Identity $UserDN -Properties lastLogon -ErrorAction Stop
   $raw=0
   if($null -ne $u.lastLogon){$raw=[int64]$u.lastLogon}
   if($raw -gt $bestRaw){
    $bestRaw=$raw;$bestDC=[string]$dc
    if($raw -gt 0){$bestDate=[DateTime]::FromFileTimeUtc($raw).ToLocalTime()}
   }
  }catch{}
 }
 [pscustomobject]@{LastLogon=$bestDate;LastLogonRaw=$bestRaw;LastLogonDC=$bestDC}
}

function AuditUsers{
 Section 'Audit des utilisateurs'
 $dcs=@()
 try{$dcs=@(Get-ADDomainController -Filter * @ADParams|Select-Object -ExpandProperty HostName)}catch{}
 if($dcs.Count -eq 0 -and $DomainController){$dcs=@($DomainController)}
 if($dcs.Count -eq 0){try{$dcs=@((Get-ADDomain @ADParams).PDCEmulator)}catch{}}

 $x=@(Get-ADUser @ADParams -Filter * -Properties *|ForEach-Object{
  $u=$_
  $uac=[int64]$u.UserAccountControl
  $uacComputed=0
  if($null -ne $u.'msDS-User-Account-Control-Computed'){$uacComputed=[int64]$u.'msDS-User-Account-Control-Computed'}
  $enabledByUAC=(($uac -band 2) -eq 0)
  $lockedByComputed=(($uacComputed -band 16) -ne 0)
  $expiredByComputed=(($uacComputed -band 8388608) -ne 0)
  $g=@(Get-ADPrincipalGroupMembership @ADParams -Identity $u.DistinguishedName -ErrorAction SilentlyContinue)
  $gn=@($g|Select-Object -ExpandProperty Name)
  $priv=@($g|Where-Object {$_.Name -in (PrivGroups)})
  $linkedGPOs=Get-UserLinkedGPOs $u.DistinguishedName
  $accurateLogon=Get-UserLastLogonAccurate $u.DistinguishedName $dcs

  [pscustomobject]@{
   SamAccountName=$u.SamAccountName;UserPrincipalName=$u.UserPrincipalName;Name=$u.Name;GivenName=$u.GivenName;Initials=$u.Initials;MiddleName=$u.MiddleName;Surname=$u.Surname;DisplayName=$u.DisplayName
   Enabled=$enabledByUAC;EnabledFromADModule=$u.Enabled;StatusConsistency=($enabledByUAC -eq [bool]$u.Enabled)
   AccountType=(AccountType $uac);ObjectClass=($u.ObjectClass -join ',');ObjectCategory=$u.ObjectCategory
   UserAccountControl=$uac;UserAccountControlHex=('0x{0:X8}' -f $uac);UserAccountControlFlags=(AccountType $uac)
   UserAccountControlComputed=$uacComputed;UserAccountControlComputedHex=('0x{0:X8}' -f $uacComputed)
   DistinguishedName=$u.DistinguishedName;CanonicalName=$u.CanonicalName;ObjectGUID=$u.ObjectGUID.Guid;SID=$u.SID.Value
   Description=$u.Description;Department=$u.Department;Title=$u.Title;Company=$u.Company;Division=$u.Division;Office=$u.Office;OfficePhone=$u.OfficePhone;MobilePhone=$u.MobilePhone;EmailAddress=$u.Mail;EmployeeId=$u.EmployeeID;EmployeeNumber=$u.EmployeeNumber;Manager=$u.Manager
   StreetAddress=$u.StreetAddress;City=$u.City;State=$u.State;PostalCode=$u.PostalCode;Country=$u.Country;CountryCode=$u.CountryCode
   HomeDirectory=$u.HomeDirectory;HomeDrive=$u.HomeDrive;ScriptPath=$u.ScriptPath;ProfilePath=$u.ProfilePath
   Created=$u.Created;Modified=$u.Modified;WhenCreated=$u.WhenCreated;WhenChanged=$u.WhenChanged
   LastLogon=$accurateLogon.LastLogon;LastLogonRaw=$accurateLogon.LastLogonRaw;LastLogonDC=$accurateLogon.LastLogonDC
   LastLogonDate=$u.LastLogonDate;LastLogonTimestamp=$u.LastLogonTimestamp;LastLogonTimestampRaw=$u.lastLogonTimestamp
   LastBadPasswordAttempt=$u.LastBadPasswordAttempt;BadLogonCount=$u.BadLogonCount;BadPwdCount=$u.BadPwdCount;BadPasswordTime=$u.badPasswordTime;LockoutTime=$u.lockoutTime
   LockedOut=$lockedByComputed;LockedOutFromADModule=$u.LockedOut;PasswordExpired=$expiredByComputed;PasswordExpiredFromADModule=$u.PasswordExpired
   PasswordLastSet=$u.PasswordLastSet;PwdLastSetRaw=$u.pwdLastSet;PasswordNeverExpires=$u.PasswordNeverExpires;PasswordNotRequired=$u.PasswordNotRequired;CannotChangePassword=$u.CannotChangePassword
   AccountExpirationDate=$u.AccountExpirationDate;AccountExpiresRaw=$u.accountExpires;SmartcardLogonRequired=$u.SmartcardLogonRequired
   DoesNotRequirePreAuth=$u.DoesNotRequirePreAuth;TrustedForDelegation=$u.TrustedForDelegation;TrustedToAuthForDelegation=$u.TrustedToAuthForDelegation
   HomePhone=$u.HomePhone;Fax=$u.Fax;Info=$u.Info;WebPage=$u.wWWHomePage
   PrimaryGroupID=$u.PrimaryGroupID;MemberOf=(@($u.MemberOf)-join ' | ')
   Groups=($gn -join ' | ');GroupCount=$gn.Count;PrivilegedGroups=(($priv|Select-Object -ExpandProperty Name)-join ' | ');PrivilegedGroupCount=$priv.Count;IsPrivileged=($priv.Count -gt 0)
   ServicePrincipalNames=(@($u.ServicePrincipalNames)-join ' | ');SPNCount=@($u.ServicePrincipalNames).Count
   LinkedGPOs=($linkedGPOs -join ' | ');LinkedGPOCount=$linkedGPOs.Count
   DistinguishedNameParent=($u.DistinguishedName -replace '^CN=[^,]+,','');RawADAttributes=(Get-ADUserRawAttributes $u)
  }
 })
 $Script:Results.Users=$x
 Ok ($x.Count.ToString()+' utilisateurs audites.')
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
  $stale=($_.LastLogonDate -and $_.LastLogonDate -lt  (Get-Date).AddDays(-90))
  if($stale -and  $_.Enabled){Finding Medium Computers 'Ordinateur inactif > 90 jours' $_.Name ('Derniere connexion: '+$_.LastLogonDate) 'Desactiver puis traiter selon la procedure de parc.'}
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
  $rp=$null;if($IncludeGPOReports){try{[xml]$gpoXml=Get-GPOReport -Guid $_.Id -ReportType Xml -ErrorAction Stop;$rp='IncludedInMemory'}catch{Warn ('Rapport GPO impossible: '+$_.DisplayName+' / '+$_.Exception.Message)}}
  [pscustomobject]@{Id=$_.Id.Guid;DisplayName=$_.DisplayName;DomainName=$_.DomainName;Owner=$_.Owner;GpoStatus=$_.GpoStatus;Description=$_.Description;CreationTime=$_.CreationTime;ModificationTime=$_.ModificationTime;WmiFilter=$_.WmiFilter.Name;ReportXml=$rp}
 });$Script:Results.GPOs=$x;Ok ($x.Count.ToString()+' GPO auditees.')
}
function AuditDomain{
 Section 'Audit du domaine';$d=Get-ADDomain @ADParams;$f=Get-ADForest @ADParams;$p=Get-ADDefaultDomainPasswordPolicy @ADParams
 if($p.MinPasswordLength -lt  12){Finding Medium Domain 'Longueur de mot de passe faible' $d.DNSRoot ('Minimum: '+$p.MinPasswordLength) 'Viser 12 caracteres ou davantage.'}
 if($p.PasswordHistoryCount -lt  10){Finding Low Domain 'Historique de mot de passe faible' $d.DNSRoot ('Historique: '+$p.PasswordHistoryCount) 'Augmenter l historique.'}
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
 Section 'Audit LAPS';$x=@(Get-ADComputer @ADParams -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'|%{[pscustomobject]@{Computer=$_.Name;LegacyLAPSAttributePresent=($null -ne  $_.'ms-Mcs-AdmPwdExpirationTime');LegacyLAPSExpiration=$_.'ms-Mcs-AdmPwdExpirationTime';WindowsLAPSAttributePresent=($null -ne  $_.'msLAPS-PasswordExpirationTime');WindowsLAPSExpiration=$_.'msLAPS-PasswordExpirationTime';DistinguishedName=$_.DistinguishedName}})
 $Script:Results.LAPS=$x;$none=@($x|?{-not $_.LegacyLAPSAttributePresent -and  -not $_.WindowsLAPSAttributePresent});if($none.Count -gt  0){Finding Medium LAPS 'Ordinateurs sans trace LAPS' 'AD Computers' ($none.Count.ToString()+' ordinateur(s).') 'Verifier la couverture Windows LAPS.'};Ok ($x.Count.ToString()+' ordinateurs verifies pour LAPS.')
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
 Section 'Audit de la sante AD';$x=@();if(Cmd Get-ADReplicationPartnerMetadata){try{$x=@(Get-ADDomainController -Filter * @ADParams|%{Get-ADReplicationPartnerMetadata -Target $_.HostName -Scope Server -ErrorAction SilentlyContinue|select Server,Partner,LastReplicationSuccess,LastReplicationResult,ConsecutiveReplicationFailures,LastReplicationAttempt});foreach($z in $x){if($z.ConsecutiveReplicationFailures -gt  0 -or  $z.LastReplicationResult -ne  0){Finding High Health 'Echec de replication AD' (($z.Server)+' -> '+($z.Partner)) ('Resultat='+$z.LastReplicationResult+'; echecs='+$z.ConsecutiveReplicationFailures) 'Analyser DNS, RPC, Kerberos et les journaux AD.'}}}catch{Warn ('Replication indisponible: '+$_.Exception.Message)}};$Script:Results.Health=$x;Ok ($x.Count.ToString()+' relations de replication.')
}
function AuditPrivileged{
 Section 'Audit des privileges';$rows=@();foreach($name in (PrivGroups)){try{$g=Get-ADGroup @ADParams -Identity $name -Properties *;$m=@(Get-ADGroupMember @ADParams -Identity $g.DistinguishedName -Recursive -ErrorAction SilentlyContinue);$rows+=[pscustomobject]@{Group=$name;Exists=$true;MemberCount=$m.Count;Members=(($m|select -Expand Name)-join ' | ');DistinguishedName=$g.DistinguishedName};if($m.Count){Finding Medium Privileged ('Groupe privilegie: '+$name) $name ($m.Count.ToString()+' membre(s).') 'Verifier les membres.'}}catch{$rows+=[pscustomobject]@{Group=$name;Exists=$false;MemberCount=0;Members='';DistinguishedName=''}}};$Script:Results.Privileged=$rows;Ok ($rows.Count.ToString()+' groupes sensibles verifies.')
}
function AuditKerberos{
 Section 'Audit Kerberos';$rows=@(Get-ADUser @ADParams -Filter * -Properties DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,Enabled,PasswordLastSet|%{if($_.DoesNotRequirePreAuth -or  $_.TrustedForDelegation -or  $_.TrustedToAuthForDelegation -or  @($_.ServicePrincipalName).Count){[pscustomobject]@{Account=$_.SamAccountName;Enabled=$_.Enabled;ASREP=$_.DoesNotRequirePreAuth;UnconstrainedDelegation=$_.TrustedForDelegation;ConstrainedDelegation=$_.TrustedToAuthForDelegation;SPNCount=@($_.ServicePrincipalName).Count;SPNs=(@($_.ServicePrincipalName)-join ' | ');PasswordLastSet=$_.PasswordLastSet;DistinguishedName=$_.DistinguishedName}}});foreach($r in $rows){if($r.ASREP){Finding High Kerberos 'AS-REP roastable account' $r.Account 'Pre-authentification desactivee.' 'Reactiver la pre-authentification.'};if($r.UnconstrainedDelegation){Finding High Kerberos 'Delegation non contrainte' $r.Account 'TrustedForDelegation active.' 'Verifier et supprimer si inutile.'}};$Script:Results.Kerberos=$rows;Ok ($rows.Count.ToString()+' comptes sensibles.')
}
function AuditPasswordPolicies{
 Section 'Audit des politiques de mots de passe';$p=Get-ADDefaultDomainPasswordPolicy @ADParams;$rows=@([pscustomobject]@{Type='DefaultDomain';Name='Default Domain Policy';MinPasswordLength=$p.MinPasswordLength;PasswordHistoryCount=$p.PasswordHistoryCount;ComplexityEnabled=$p.ComplexityEnabled;MaxPasswordAge=$p.MaxPasswordAge;MinPasswordAge=$p.MinPasswordAge;LockoutThreshold=$p.LockoutThreshold});if(Cmd Get-ADFineGrainedPasswordPolicy){$rows+=@(Get-ADFineGrainedPasswordPolicy @ADParams -Filter * -Properties *|%{[pscustomobject]@{Type='FineGrained';Name=$_.Name;Precedence=$_.Precedence;MinPasswordLength=$_.MinPasswordLength;PasswordHistoryCount=$_.PasswordHistoryCount;ComplexityEnabled=$_.ComplexityEnabled;MaxPasswordAge=$_.MaxPasswordAge;LockoutThreshold=$_.LockoutThreshold;AppliesTo=(@($_.AppliesTo)-join ' | ')}})};$Script:Results.PasswordPolicies=$rows;Ok ($rows.Count.ToString()+' politiques.')
}
function AuditSchema{
 Section 'Audit du schema';$s=Get-ADObject @ADParams -SearchBase ((Get-ADRootDSE @ADParams).schemaNamingContext) -LDAPFilter '(|(objectClass=classSchema)(objectClass=attributeSchema))' -Properties lDAPDisplayName,objectClass,adminDisplayName,whenCreated,whenChanged;$Script:Results.Schema=@($s|%{[pscustomobject]@{LDAPDisplayName=$_.lDAPDisplayName;ObjectClass=($_.objectClass-join ',');AdminDisplayName=$_.adminDisplayName;WhenCreated=$_.whenCreated;WhenChanged=$_.whenChanged;DistinguishedName=$_.DistinguishedName}});Ok ($Script:Results.Schema.Count.ToString()+' objets schema.')
}
function AuditADCS{
 Section 'Audit AD CS';$config=(Get-ADRootDSE @ADParams).configurationNamingContext;$rows=@(Get-ADObject @ADParams -SearchBase $config -LDAPFilter '(|(objectClass=pKIEnrollmentService)(objectClass=pKICertificateTemplate))' -Properties displayName,cn,certificateTemplates,flags,msPKI-Enrollment-Flag,msPKI-Certificate-Name-Flag,msPKI-Private-Key-Flag|%{[pscustomobject]@{Name=$_.displayName;CN=$_.cn;ObjectClass=($_.objectClass-join ',');CertificateTemplates=(@($_.certificateTemplates)-join ' | ');Flags=$_.flags;EnrollmentFlags=$_.'msPKI-Enrollment-Flag';CertificateNameFlags=$_.'msPKI-Certificate-Name-Flag';PrivateKeyFlags=$_.'msPKI-Private-Key-Flag';DistinguishedName=$_.DistinguishedName}});$Script:Results.ADCS=$rows;if($rows.Count){Finding Info ADCS 'Infrastructure AD CS detectee' 'AD CS' ($rows.Count.ToString()+' objets.') 'Faire une revue PKI dediee.'};Ok ($rows.Count.ToString()+' objets AD CS.')
}
function AuditRecycleBin{
 Section 'Audit de la corbeille AD';$x=@(Get-ADOptionalFeature @ADParams -Filter 'Name -eq "Recycle Bin Feature"' -Properties EnabledScopes|%{[pscustomobject]@{Name=$_.Name;Enabled=($_.EnabledScopes.Count -gt 0);EnabledScopes=(@($_.EnabledScopes)-join ' | ');DistinguishedName=$_.DistinguishedName}});$Script:Results.RecycleBin=$x;if($x.Count -and  -not $x[0].Enabled){Finding High RecycleBin 'Corbeille AD inactive' 'Recycle Bin Feature' 'La corbeille semble inactive.' 'Verifier la politique de restauration.'};Ok 'Corbeille AD auditee.'
}
function AuditAdminSDHolder{
 Section 'Audit AdminSDHolder';$d=Get-ADDomain @ADParams;$dn=('CN=AdminSDHolder,CN=System,'+$d.DistinguishedName);$a=Get-Acl ('AD:\'+$dn);$Script:Results.AdminSDHolder=@($a.Access|%{[pscustomobject]@{IdentityReference=$_.IdentityReference;ActiveDirectoryRights=$_.ActiveDirectoryRights;AccessControlType=$_.AccessControlType;ObjectType=$_.ObjectType;IsInherited=$_.IsInherited}});Ok ($Script:Results.AdminSDHolder.Count.ToString()+' ACE.')
}
function AuditGPOAnalysis{
 Section 'Analyse GPO';if(-not(Cmd Get-GPOReport)){Warn 'Get-GPOReport indisponible.';return};$rows=@();foreach($g in @(Get-GPO -All @ADParams)){try{[xml]$xml=Get-GPOReport -Guid $g.Id -ReportType Xml;$t=$xml.OuterXml;$f=@();if($t-match '(?i)EnableLUA.*false|FilterAdministratorToken.*false'){$f+='UAC weakening'};if($t-match '(?i)fDenyTSConnections.*0|Terminal Services'){$f+='RDP'};if($t-match '(?i)SMB1|LanmanServer.*SMB1'){$f+='SMB legacy'};if($t-match '(?i)DisableRealtimeMonitoring|DisableAntiSpyware'){$f+='Defender'};if($t-match '(?i)SeDebugPrivilege|SeTakeOwnershipPrivilege|SeBackupPrivilege'){$f+='Privileges sensibles'};if($f.Count){Finding Medium GPO ('Configuration sensible: '+$g.DisplayName) $g.DisplayName ($f-join ', ') 'Revoir la configuration.'};$rows+=[pscustomobject]@{Id=$g.Id.Guid;DisplayName=$g.DisplayName;Status=$g.GpoStatus;Flags=($f-join ' | ');Owner=$g.Owner;Created=$g.CreationTime;Modified=$g.ModificationTime}}catch{Warn ('GPO: '+$g.DisplayName+' / '+$_.Exception.Message)}};$Script:Results.GPOAnalysis=$rows;Ok ($rows.Count.ToString()+' GPO analysees.')
}
function ExportResults{
 try{
  $domainName=''
  try{$domainName=[string](Get-ADDomain @ADParams).DNSRoot}catch{}
  $report=New-Object PSObject
  Add-Member -InputObject $report -MemberType NoteProperty -Name Tool -Value 'AD Advanced Audit'
  Add-Member -InputObject $report -MemberType NoteProperty -Name Version -Value $Script:AuditVersion
  Add-Member -InputObject $report -MemberType NoteProperty -Name StartedAt -Value ([string]$Script:StartedAt)
  Add-Member -InputObject $report -MemberType NoteProperty -Name FinishedAt -Value ([string](Get-Date))
  Add-Member -InputObject $report -MemberType NoteProperty -Name Domain -Value $domainName
  Add-Member -InputObject $report -MemberType NoteProperty -Name ReadOnly -Value $true
  Add-Member -InputObject $report -MemberType NoteProperty -Name SelectedModules -Value @($Script:SelectedModules)
  Add-Member -InputObject $report -MemberType NoteProperty -Name Findings -Value @($Script:Findings)
  Add-Member -InputObject $report -MemberType NoteProperty -Name Results -Value $Script:Results
  New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop|Out-Null
  if($ExportFormat -eq 'JSON' -or $ExportFormat -eq 'Both'){
   $file=Join-Path $OutputPath 'AD-Audit.json'
   $json=ConvertTo-Json -InputObject $report -Depth 10
   [System.IO.File]::WriteAllText($file,$json,(New-Object System.Text.UTF8Encoding($false)))
   Ok ('Export JSON: '+$file)
  }
  if($ExportFormat -eq 'HTML' -or $ExportFormat -eq 'Both'){
   $htmlFile=Join-Path $OutputPath 'AD-Audit.html'
   $json=ConvertTo-Json -InputObject $report -Depth 10
   $safe=[System.Net.WebUtility]::HtmlEncode([string]$json)
   $html='<!doctype html><html><head><meta charset="utf-8"><title>AD Advanced Audit</title></head><body><h1>AD Advanced Audit</h1><pre>'+ $safe +'</pre></body></html>'
   [System.IO.File]::WriteAllText($htmlFile,$html,(New-Object System.Text.UTF8Encoding($false)))
   Ok ('Export HTML: '+$htmlFile)
  }
 }catch{
  throw ('Erreur pendant l export: '+$_.Exception.Message)
 }
}
function SelectModules{
 Section 'Selection des modules'
 $k=@($ModuleDefinitions.Keys)
 for($i=0;$i -lt $k.Count;$i++){
  W(('[{0,2}] {1,-18} {2}' -f ($i+1),$k[$i],$ModuleDefinitions[$k[$i]]))
 }
 W ''
 W '[A] Tout auditer'
 W '[Q] Quitter'
 $answer=Read-Host 'Votre choix (ex: 1,2,5 ou A)'
 $Script:SelectedModules=New-Object System.Collections.Generic.List[string]
 if([string]::IsNullOrWhiteSpace($answer)){return}
 if($answer.Trim().ToUpper() -eq 'A'){
  foreach($name in $k){[void]$Script:SelectedModules.Add([string]$name)}
  return
 }
 if($answer.Trim().ToUpper() -eq 'Q'){return}
 foreach($part in $answer.Split(',')){
  $value=$part.Trim()
  if($value -match '^\d+$'){
   $idx=([int]$value)-1
   if($idx -ge 0 -and $idx -lt $k.Count){[void]$Script:SelectedModules.Add([string]$k[$idx])}
  }
 }
}
function Run($n){
 $names=@($n)
 if($names.Count -ne 1){throw ('Module invalide: valeur recue de type '+$n.GetType().FullName+' avec '+$names.Count+' element(s).')}
 $name=[string]$names[0]
 switch($name){
  Users{AuditUsers;break};Groups{AuditGroups;break};Computers{AuditComputers;break};OUs{AuditOUs;break};GPOs{AuditGPOs;break};Domain{AuditDomain;break};DCs{AuditDCs;break};Sites{AuditSites;break};Trusts{AuditTrusts;break};DNS{AuditDNS;break};Delegation{AuditDelegation;break};SPNs{AuditSPNs;break};LAPS{AuditLAPS;break};Health{AuditHealth;break};Privileged{AuditPrivileged;break};Kerberos{AuditKerberos;break};PasswordPolicies{AuditPasswordPolicies;break};Schema{AuditSchema;break};ADCS{AuditADCS;break};RecycleBin{AuditRecycleBin;break};AdminSDHolder{AuditAdminSDHolder;break};GPOAnalysis{AuditGPOAnalysis;break}
  default{throw ('Module inconnu: ['+$name+'] Type='+$names[0].GetType().FullName)}
 }
}
Section ('AD Advanced Audit v'+$Script:AuditVersion)
if(-not(Cmd Get-ADDomain)){throw 'Le module ActiveDirectory est requis (RSAT).'}

$Script:SelectedModules=New-Object System.Collections.Generic.List[string]
if($PSBoundParameters.ContainsKey('Modules') -and $null -ne $Modules -and @($Modules).Count -gt 0){
 foreach($name in @($Modules)){
  if($null -ne $name -and $ModuleDefinitions.Contains([string]$name)){[void]$Script:SelectedModules.Add([string]$name)}
 }
}elseif($Mode -eq 'All'){
 foreach($name in @($ModuleDefinitions.Keys)){[void]$Script:SelectedModules.Add([string]$name)}
}else{
 SelectModules
}
if($Script:SelectedModules.Count -eq 0){throw 'Aucun module selectionne.'}
New-Item -ItemType Directory -Path $OutputPath -Force|Out-Null
foreach($moduleName in @($Script:SelectedModules)){
 try{Run $moduleName}catch{Warn ('Module '+$moduleName+' en erreur: '+$_.Exception.Message);Finding High Engine ('Echec du module '+$moduleName) $moduleName $_.Exception.Message 'Verifier les droits, RSAT et la connectivite.'}
}
ExportResults;Section 'Fin de l audit';W ('Modules: '+($Script:Results.Keys-join ', '));W ('Findings: '+$Script:Findings.Count);W ('Repertoire: '+$OutputPath)
