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
$Script:AuditVersion='1.4.0';$Script:StartedAt=Get-Date
$Script:Results=[ordered]@{};$Script:Findings=New-Object System.Collections.Generic.List[object]
$ModuleDefinitions=[ordered]@{
 Users='Comptes utilisateurs';Groups='Groupes et privileges';Computers='Ordinateurs';OUs='Unites organisationnelles';GPOs='GPO et analyse';Domain='Domaine et politiques';DCs='Controleurs de domaine';Sites='Sites et replication';Trusts='Relations de confiance';DNS='DNS';Delegation='Delegations ACL';SPNs='SPN';LAPS='LAPS';Health='Sante AD';Privileged='Privileges';Kerberos='Kerberos';PasswordPolicies='FGPP';Schema='Schema AD';ADCS='AD CS / PKI';RecycleBin='Corbeille AD';AdminSDHolder='AdminSDHolder';GPOAnalysis='Analyse GPO approfondie';Security='Collecte sécurité approfondie'
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
function Recurse([string]$dn){
 try{
  $base=(Get-ADRootDSE @ADParams).defaultNamingContext
  $filter='(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:='+$dn+'))'
  return @(Get-ADObject @ADParams -SearchBase $base -LDAPFilter $filter -Properties objectClass,Name,SamAccountName,DistinguishedName -ErrorAction Stop)
 }catch{
  Warn ('Membres recursifs indisponibles: '+$dn+' / '+$_.Exception.Message)
  @()
 }
}
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
    if($link.GpoId){[void]$result.Add(([string]$link.DisplayName)+' ['+([string]$link.GpoId)+'] [Direct]')}
   }
   foreach($link in @($inheritance.InheritedGpoLinks)){
    if($link.GpoId){[void]$result.Add(([string]$link.DisplayName)+' ['+([string]$link.GpoId)+'] [Inherited]')}
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
   if($v -is [byte[]]){
    $raw[$p.Name]=[Convert]::ToBase64String($v)
   }elseif($v -is [datetime]){
    $raw[$p.Name]=$v.ToString('o')
   }elseif($v -is [guid]){
    $raw[$p.Name]=$v.ToString()
   }elseif($v -is [System.Security.Principal.SecurityIdentifier]){
    $raw[$p.Name]=$v.Value
   }elseif($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])){
    $items=New-Object System.Collections.Generic.List[string]
    foreach($item in $v){
     if($null -ne $item){[void]$items.Add([string]$item)}
    }
    if($items.Count -gt 0){$raw[$p.Name]=@($items.ToArray())}
   }else{
    $raw[$p.Name]=$v
   }
  }catch{}
 }
 return $raw
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

 $x=@(Get-ADUser @ADParams -Filter * -Properties *,msDS-User-Account-Control-Computed|ForEach-Object{
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
  $rp=$null;if($IncludeGPOReports){try{[xml]$gpoXml=Get-GPOReport -Guid $_.Id -ReportType Xml -ErrorAction Stop;$rp=$gpoXml.OuterXml}catch{Warn ('Rapport GPO impossible: '+$_.DisplayName+' / '+$_.Exception.Message)}}
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
 Section 'Audit des SPN'
 $x=@()
 $users=@(Get-ADUser @ADParams -Filter * -Properties ServicePrincipalName,Enabled,SamAccountName,DistinguishedName)
 foreach($u in $users){
  foreach($spn in @($u.ServicePrincipalName)){
   if(-not [string]::IsNullOrWhiteSpace([string]$spn)){
    $x+=[pscustomobject]@{Account=$u.SamAccountName;Enabled=$u.Enabled;SPN=[string]$spn;DistinguishedName=$u.DistinguishedName}
   }
  }
 }
 $Script:Results.SPNs=$x
 Ok ($x.Count.ToString()+' SPN utilisateur(s).')
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
 Section 'Audit DNS'
 $x=@()
 if(Cmd Get-DnsServerZone){
  try{
   $dnsServer=$DomainController
   if([string]::IsNullOrWhiteSpace($dnsServer)){
    try{$dnsServer=(Get-ADDomainController -Discover -Service PrimaryDC @ADParams).HostName}catch{}
   }
   if([string]::IsNullOrWhiteSpace($dnsServer)){
    try{$dnsServer=(Get-ADDomain @ADParams).PDCEmulator}catch{}
   }
   if([string]::IsNullOrWhiteSpace($dnsServer)){$x=@(Get-DnsServerZone -ErrorAction Stop)}
   else{$x=@(Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop)}
  }catch{Warn ('DNS indisponible: '+$_.Exception.Message)}
 }else{Warn 'Module DnsServer absent. DNS ignore.'}
 $Script:Results.DNS=$x
 Ok ($x.Count.ToString()+' zone(s) DNS.')
}
function AuditHealth{
 Section 'Audit de la sante AD';$x=@();if(Cmd Get-ADReplicationPartnerMetadata){try{$x=@(Get-ADDomainController -Filter * @ADParams|%{Get-ADReplicationPartnerMetadata -Target $_.HostName -Scope Server -ErrorAction SilentlyContinue|select Server,Partner,LastReplicationSuccess,LastReplicationResult,ConsecutiveReplicationFailures,LastReplicationAttempt});foreach($z in $x){if($z.ConsecutiveReplicationFailures -gt  0 -or  $z.LastReplicationResult -ne  0){Finding High Health 'Echec de replication AD' (($z.Server)+' -> '+($z.Partner)) ('Resultat='+$z.LastReplicationResult+'; echecs='+$z.ConsecutiveReplicationFailures) 'Analyser DNS, RPC, Kerberos et les journaux AD.'}}}catch{Warn ('Replication indisponible: '+$_.Exception.Message)}};$Script:Results.Health=$x;Ok ($x.Count.ToString()+' relations de replication.')
}
function AuditPrivileged{
 Section 'Audit des privileges';$rows=@();$names=@(PrivGroups);$i=0
 foreach($name in $names){$i++
  try{
   W ('[*] Groupe sensible '+$i+'/'+$names.Count+': '+$name)
   $g=Get-ADGroup @ADParams -Identity $name -Properties * -ErrorAction Stop
   $m=@(Recurse $g.DistinguishedName)
   $rows+=[pscustomobject]@{Group=$name;Exists=$true;MemberCount=$m.Count;Members=(($m|select -Expand Name)-join ' | ');DistinguishedName=$g.DistinguishedName}
   if($m.Count){Finding Medium Privileged ('Groupe privilegie: '+$name) $name ($m.Count.ToString()+' membre(s).') 'Verifier les membres.'}
  }catch{$rows+=[pscustomobject]@{Group=$name;Exists=$false;MemberCount=0;Members='';DistinguishedName=''}}
 }
 $Script:Results.Privileged=$rows;Ok ($rows.Count.ToString()+' groupes sensibles verifies.')
}
function AuditKerberos{
 Section 'Audit Kerberos'
 $rows=New-Object System.Collections.Generic.List[object]
 $users=@(Get-ADUser @ADParams -Filter * -Properties DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,Enabled,PasswordLastSet,'msDS-AllowedToDelegateTo')
 foreach($u in $users){
  $spns=@($u.ServicePrincipalName);$targets=@($u.'msDS-AllowedToDelegateTo')
  if($u.DoesNotRequirePreAuth -or $u.TrustedForDelegation -or $u.TrustedToAuthForDelegation -or $spns.Count -or $targets.Count){
   [void]$rows.Add([pscustomobject]@{ObjectType='User';Account=$u.SamAccountName;Enabled=$u.Enabled;ASREP=$u.DoesNotRequirePreAuth;UnconstrainedDelegation=$u.TrustedForDelegation;ProtocolTransition=$u.TrustedToAuthForDelegation;ConstrainedDelegationTargets=($targets-join ' | ');SPNCount=$spns.Count;SPNs=($spns-join ' | ');PasswordLastSet=$u.PasswordLastSet;DistinguishedName=$u.DistinguishedName})
  }
 }
 $computers=@(Get-ADComputer @ADParams -Filter * -Properties TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',Enabled)
 foreach($co in $computers){
  $spns=@($co.ServicePrincipalName);$targets=@($co.'msDS-AllowedToDelegateTo');$rbcd=($null -ne $co.'msDS-AllowedToActOnBehalfOfOtherIdentity')
  if($co.TrustedForDelegation -or $co.TrustedToAuthForDelegation -or $spns.Count -or $targets.Count -or $rbcd){
   [void]$rows.Add([pscustomobject]@{ObjectType='Computer';Account=$co.Name;Enabled=$co.Enabled;ASREP=$false;UnconstrainedDelegation=$co.TrustedForDelegation;ProtocolTransition=$co.TrustedToAuthForDelegation;ConstrainedDelegationTargets=($targets-join ' | ');ResourceBasedConstrainedDelegation=$rbcd;SPNCount=$spns.Count;SPNs=($spns-join ' | ');PasswordLastSet=$co.PasswordLastSet;DistinguishedName=$co.DistinguishedName})
  }
 }
 $Script:Results.Kerberos=@($rows)
 foreach($r in @($rows)){
  if($r.ASREP){Finding High Kerberos 'AS-REP roastable account' $r.Account 'Pre-authentification desactivee.' 'Reactiver la pre-authentification.'}
  if($r.UnconstrainedDelegation){Finding High Kerberos 'Delegation non contrainte' $r.Account 'TrustedForDelegation active.' 'Verifier et supprimer si inutile.'}
  if($r.ConstrainedDelegationTargets){Finding Medium Kerberos 'Delegation contrainte configuree' $r.Account ($r.ConstrainedDelegationTargets) 'Verifier que chaque SPN cible est strictement necessaire.'}
  if($r.ResourceBasedConstrainedDelegation){Finding Medium Kerberos 'RBCD configuree' $r.Account 'msDS-AllowedToActOnBehalfOfOtherIdentity est present.' 'Identifier les principaux autorises et verifier la legitimite de la delegation.'}
 }
 Ok ($rows.Count.ToString()+' comptes et ordinateurs sensibles.')
}
function AuditSecurity{
 Section 'Collecte securite approfondie'
 $rows=New-Object System.Collections.Generic.List[object]
 $users=@(Get-ADUser @ADParams -Filter * -Properties adminCount,servicePrincipalName,'msDS-SupportedEncryptionTypes','msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',sIDHistory,altSecurityIdentities,'msDS-KeyCredentialLink',userCertificate,userAccountControl,pwdLastSet,accountExpires,primaryGroupID,adminDisplayName,description,Enabled)
 foreach($u in $users){
  $uac=[int64]$u.UserAccountControl
  $sidHistory=@($u.sIDHistory)
  $spns=@($u.ServicePrincipalName)
  $deleg=@($u.'msDS-AllowedToDelegateTo')
  $keyCred=@($u.'msDS-KeyCredentialLink')
  $certs=@($u.userCertificate)
  $adminCount=($null -ne $u.adminCount -and [int]$u.adminCount -eq 1)
  $risky=$adminCount -or $spns.Count -gt 0 -or $deleg.Count -gt 0 -or $sidHistory.Count -gt 0 -or $keyCred.Count -gt 0 -or $certs.Count -gt 0
  if($risky){
   [void]$rows.Add([pscustomobject]@{
    ObjectType='User';Account=$u.SamAccountName;Enabled=$u.Enabled;AdminCount=$u.adminCount;PrivilegedMarker=$adminCount
    SPNCount=$spns.Count;SPNs=($spns -join ' | ');ConstrainedDelegationTargets=($deleg -join ' | ')
    SIDHistoryPresent=($sidHistory.Count -gt 0);SIDHistoryCount=$sidHistory.Count
    AltSecurityIdentitiesPresent=(@($u.altSecurityIdentities).Count -gt 0)
    KeyCredentialLinkPresent=($keyCred.Count -gt 0);UserCertificatePresent=($certs.Count -gt 0)
    SupportedEncryptionTypes=$u.'msDS-SupportedEncryptionTypes';UserAccountControl=$uac
    PasswordLastSet=$u.PasswordLastSet;AccountExpirationDate=$u.AccountExpirationDate;PrimaryGroupID=$u.PrimaryGroupID
    DistinguishedName=$u.DistinguishedName
   })
  }
  if($sidHistory.Count -gt 0){Finding High Security 'SIDHistory present sur un compte' $u.SamAccountName ($sidHistory.Count.ToString()+' entree(s) SIDHistory.') 'Verifier chaque SID historique et sa necessite.'}
  if($keyCred.Count -gt 0){Finding Medium Security 'Credential key presente' $u.SamAccountName 'msDS-KeyCredentialLink est present.' 'Verifier les Windows Hello for Business/FIDO et les identites attendues.'}
  if($u.altSecurityIdentities){Finding Medium Security 'Identite alternative configuree' $u.SamAccountName 'altSecurityIdentities est renseigne.' 'Verifier l usage de certificats et la chaine de confiance.'}
 }
 $computers=@(Get-ADComputer @ADParams -Filter * -Properties adminCount,TrustedForDelegation,TrustedToAuthForDelegation,'msDS-SupportedEncryptionTypes','msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',sIDHistory,servicePrincipalName,userCertificate,userAccountControl,pwdLastSet,primaryGroupID,Enabled,OperatingSystem,OperatingSystemVersion)
 foreach($co in $computers){
  $sidHistory=@($co.sIDHistory);$spns=@($co.ServicePrincipalName);$deleg=@($co.'msDS-AllowedToDelegateTo');$rbcd=$null -ne $co.'msDS-AllowedToActOnBehalfOfOtherIdentity'
  $adminCount=($null -ne $co.adminCount -and [int]$co.adminCount -eq 1)
  $risky=$adminCount -or $co.TrustedForDelegation -or $co.TrustedToAuthForDelegation -or $deleg.Count -gt 0 -or $rbcd -or $sidHistory.Count -gt 0
  if($risky){
   [void]$rows.Add([pscustomobject]@{
    ObjectType='Computer';Account=$co.Name;Enabled=$co.Enabled;AdminCount=$co.adminCount;PrivilegedMarker=$adminCount
    SPNCount=$spns.Count;SPNs=($spns -join ' | ');UnconstrainedDelegation=$co.TrustedForDelegation;ProtocolTransition=$co.TrustedToAuthForDelegation
    ConstrainedDelegationTargets=($deleg -join ' | ');RBCDPresent=$rbcd;SIDHistoryPresent=($sidHistory.Count -gt 0);SIDHistoryCount=$sidHistory.Count
    SupportedEncryptionTypes=$co.'msDS-SupportedEncryptionTypes';UserAccountControl=$co.UserAccountControl
    PasswordLastSet=$co.PasswordLastSet;OperatingSystem=$co.OperatingSystem;OperatingSystemVersion=$co.OperatingSystemVersion
    DistinguishedName=$co.DistinguishedName
   })
  }
  if($sidHistory.Count -gt 0){Finding High Security 'SIDHistory present sur un ordinateur' $co.Name ($sidHistory.Count.ToString()+' entree(s) SIDHistory.') 'Verifier chaque SID historique.'}
  if($rbcd){Finding Medium Security 'RBCD configuree' $co.Name 'msDS-AllowedToActOnBehalfOfOtherIdentity est present.' 'Verifier les principals autorises.'}
 }
 $d=Get-ADDomain @ADParams
 $root=(Get-ADRootDSE @ADParams)
 $machineQuota=$null
 try{$machineQuota=(Get-ADObject @ADParams -Identity $root.defaultNamingContext -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'}catch{}
 $securityRoot=[pscustomobject]@{
  Domain=$d.DNSRoot;NetBIOSName=$d.NetBIOSName;DomainSID=$d.DomainSID.Value
  MachineAccountQuota=$machineQuota;DomainFunctionalLevel=$d.DomainMode
  ForestFunctionalLevel=(Get-ADForest @ADParams).ForestMode
  DefaultNamingContext=$root.defaultNamingContext;ConfigurationNamingContext=$root.configurationNamingContext
  SchemaNamingContext=$root.schemaNamingContext;RootDomainNamingContext=$root.rootDomainNamingContext
 }
 $groups=@(Get-ADGroup @ADParams -Filter * -Properties adminCount,sIDHistory,memberOf,managedBy,description,groupType)
 $securityGroups=New-Object System.Collections.Generic.List[object]
 foreach($g in $groups){
  $sidHistory=@($g.sIDHistory);$adminCount=($null -ne $g.adminCount -and [int]$g.adminCount -eq 1)
  if($adminCount -or $sidHistory.Count -gt 0 -or $g.Name -in (PrivGroups)){
   [void]$securityGroups.Add([pscustomobject]@{
    Name=$g.Name;SamAccountName=$g.SamAccountName;AdminCount=$g.adminCount;PrivilegedMarker=$adminCount
    SIDHistoryPresent=($sidHistory.Count -gt 0);SIDHistoryCount=$sidHistory.Count
    GroupScope=$g.GroupScope;GroupCategory=$g.GroupCategory;ManagedBy=$g.ManagedBy
    Description=$g.Description;DistinguishedName=$g.DistinguishedName;SID=$g.SID.Value
   })
  }
  if($sidHistory.Count -gt 0){Finding High Security 'SIDHistory present sur un groupe' $g.Name ($sidHistory.Count.ToString()+' entree(s) SIDHistory.') 'Verifier chaque SID historique.'}
 }
 if($null -ne $machineQuota -and [int]$machineQuota -gt 0){Finding Medium Security 'MachineAccountQuota non nul' $d.DNSRoot ('ms-DS-MachineAccountQuota='+$machineQuota) 'Verifier si les utilisateurs doivent pouvoir joindre des machines au domaine.'}
 $Script:Results.SecurityAccounts=@($rows)
 $Script:Results.SecurityGroups=@($securityGroups)
 $Script:Results.SecurityDomain=@($securityRoot)
 Ok ($rows.Count.ToString()+' objets a interet securite eleve collectes.')
 Ok 'Parametres de securite structurels du domaine collectes.'
}

function AuditPasswordPolicies{
 Section 'Audit des politiques de mots de passe';$p=Get-ADDefaultDomainPasswordPolicy @ADParams;$rows=@([pscustomobject]@{Type='DefaultDomain';Name='Default Domain Policy';MinPasswordLength=$p.MinPasswordLength;PasswordHistoryCount=$p.PasswordHistoryCount;ComplexityEnabled=$p.ComplexityEnabled;MaxPasswordAge=$p.MaxPasswordAge;MinPasswordAge=$p.MinPasswordAge;LockoutThreshold=$p.LockoutThreshold});if(Cmd Get-ADFineGrainedPasswordPolicy){$rows+=@(Get-ADFineGrainedPasswordPolicy @ADParams -Filter * -Properties *|%{[pscustomobject]@{Type='FineGrained';Name=$_.Name;Precedence=$_.Precedence;MinPasswordLength=$_.MinPasswordLength;PasswordHistoryCount=$_.PasswordHistoryCount;ComplexityEnabled=$_.ComplexityEnabled;MaxPasswordAge=$_.MaxPasswordAge;LockoutThreshold=$_.LockoutThreshold;AppliesTo=(@($_.AppliesTo)-join ' | ')}})};$Script:Results.PasswordPolicies=$rows;Ok ($rows.Count.ToString()+' politiques.')
}
function AuditSchema{
 Section 'Audit du schema';$s=Get-ADObject @ADParams -SearchBase ((Get-ADRootDSE @ADParams).schemaNamingContext) -LDAPFilter '(|(objectClass=classSchema)(objectClass=attributeSchema))' -Properties lDAPDisplayName,objectClass,adminDisplayName,whenCreated,whenChanged;$Script:Results.Schema=@($s|%{[pscustomobject]@{LDAPDisplayName=$_.lDAPDisplayName;ObjectClass=($_.objectClass-join ',');AdminDisplayName=$_.adminDisplayName;WhenCreated=$_.whenCreated;WhenChanged=$_.whenChanged;DistinguishedName=$_.DistinguishedName}});Ok ($Script:Results.Schema.Count.ToString()+' objets schema.')
}
function AuditADCS{
 Section 'Audit AD CS';$config=(Get-ADRootDSE @ADParams).configurationNamingContext;$rows=@(Get-ADObject @ADParams -SearchBase $config -LDAPFilter '(|(objectClass=pKIEnrollmentService)(objectClass=pKICertificateTemplate))' -Properties displayName,cn,certificateTemplates,flags,'msPKI-Enrollment-Flag','msPKI-Certificate-Name-Flag','msPKI-Private-Key-Flag'|%{[pscustomobject]@{Name=$_.displayName;CN=$_.cn;ObjectClass=($_.objectClass-join ',');CertificateTemplates=(@($_.certificateTemplates)-join ' | ');Flags=$_.flags;EnrollmentFlags=$_.'msPKI-Enrollment-Flag';CertificateNameFlags=$_.'msPKI-Certificate-Name-Flag';PrivateKeyFlags=$_.'msPKI-Private-Key-Flag';DistinguishedName=$_.DistinguishedName}});$Script:Results.ADCS=$rows;if($rows.Count){Finding Info ADCS 'Infrastructure AD CS detectee' 'AD CS' ($rows.Count.ToString()+' objets.') 'Faire une revue PKI dediee.'};Ok ($rows.Count.ToString()+' objets AD CS.')
}
function AuditRecycleBin{
 Section 'Audit de la corbeille AD';$x=@(Get-ADOptionalFeature @ADParams -Filter 'Name -eq "Recycle Bin Feature"' -Properties EnabledScopes|%{[pscustomobject]@{Name=$_.Name;Enabled=($_.EnabledScopes.Count -gt 0);EnabledScopes=(@($_.EnabledScopes)-join ' | ');DistinguishedName=$_.DistinguishedName}});$Script:Results.RecycleBin=$x;if($x.Count -gt 0 -and -not $x[0].Enabled){Finding High RecycleBin 'Corbeille AD inactive' 'Recycle Bin Feature' 'La corbeille semble inactive.' 'Verifier la politique de restauration.'};Ok 'Corbeille AD auditee.'
}
function AuditAdminSDHolder{
 Section 'Audit AdminSDHolder';$d=Get-ADDomain @ADParams;$dn=('CN=AdminSDHolder,CN=System,'+$d.DistinguishedName);$a=Get-Acl ('AD:\'+$dn);$Script:Results.AdminSDHolder=@($a.Access|%{[pscustomobject]@{IdentityReference=$_.IdentityReference;ActiveDirectoryRights=$_.ActiveDirectoryRights;AccessControlType=$_.AccessControlType;ObjectType=$_.ObjectType;IsInherited=$_.IsInherited}});Ok ($Script:Results.AdminSDHolder.Count.ToString()+' ACE.')
}
function AuditGPOAnalysis{
 Section 'Analyse GPO';if(-not(Cmd Get-GPOReport)){Warn 'Get-GPOReport indisponible.';return};$rows=@();foreach($g in @(Get-GPO -All @ADParams)){try{[xml]$xml=Get-GPOReport -Guid $g.Id -ReportType Xml;$t=$xml.OuterXml;$f=@();if($t-match '(?i)EnableLUA.*false|FilterAdministratorToken.*false'){$f+='UAC weakening'};if($t-match '(?i)fDenyTSConnections.*0|Terminal Services'){$f+='RDP'};if($t-match '(?i)SMB1|LanmanServer.*SMB1'){$f+='SMB legacy'};if($t-match '(?i)DisableRealtimeMonitoring|DisableAntiSpyware'){$f+='Defender'};if($t-match '(?i)SeDebugPrivilege|SeTakeOwnershipPrivilege|SeBackupPrivilege'){$f+='Privileges sensibles'};if($f.Count){Finding Medium GPO ('Configuration sensible: '+$g.DisplayName) $g.DisplayName ($f-join ', ') 'Revoir la configuration.'};$rows+=[pscustomobject]@{Id=$g.Id.Guid;DisplayName=$g.DisplayName;Status=$g.GpoStatus;Flags=($f-join ' | ');Owner=$g.Owner;Created=$g.CreationTime;Modified=$g.ModificationTime}}catch{Warn ('GPO: '+$g.DisplayName+' / '+$_.Exception.Message)}};$Script:Results.GPOAnalysis=$rows;Ok ($rows.Count.ToString()+' GPO analysees.')
}
function ConvertTo-AuditSerializable{
 param([object]$Value,[int]$Depth=0)
 if($null -eq $Value){return $null}
 if($Depth -gt 12){return [string]$Value}
 if($Value -is [string] -or $Value -is [char] -or $Value -is [bool] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or $Value -is [decimal] -or $Value -is [double] -or $Value -is [single]){return $Value}
 if($Value -is [datetime]){return $Value.ToString('o')}
 if($Value -is [guid]){return $Value.ToString()}
 if($Value -is [System.Security.Principal.SecurityIdentifier]){return $Value.Value}
 if($Value -is [byte[]]){return [Convert]::ToBase64String($Value)}
 if($Value -is [System.Xml.XmlDocument] -or $Value -is [System.Xml.XmlElement]){return $Value.OuterXml}
 if($Value -is [System.Collections.IDictionary]){
  $o=[ordered]@{}
  foreach($key in $Value.Keys){$o[[string]$key]=ConvertTo-AuditSerializable $Value[$key] ($Depth+1)}
  return $o
 }
 if($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])){
  $a=New-Object System.Collections.Generic.List[object]
  foreach($item in $Value){[void]$a.Add((ConvertTo-AuditSerializable $item ($Depth+1)))}
  return $a.ToArray()
 }
 $o=[ordered]@{}
 foreach($p in $Value.PSObject.Properties){
  if($p.MemberType -notin @('NoteProperty','Property','AliasProperty')){continue}
  try{$o[$p.Name]=ConvertTo-AuditSerializable $p.Value ($Depth+1)}catch{$o[$p.Name]=[string]$p.Value}
 }
 if($o.Count -gt 0){return $o}
 return [string]$Value
}
function Write-ExportProgress{
 param([string]$Activity,[string]$Status,[int]$Percent,[System.Diagnostics.Stopwatch]$Timer)
 if($NoConsole){return}
 $pct=[Math]::Max(0,[Math]::Min(100,$Percent))
 Write-Progress -Id 900 -Activity $Activity -Status $Status -PercentComplete $pct
}
function Format-Elapsed([System.Diagnostics.Stopwatch]$Timer){
 if($null -eq $Timer){return '00:00:00'}
 return $Timer.Elapsed.ToString('hh\\:mm\\:ss')
}

function ExportResults{
 $timer=[System.Diagnostics.Stopwatch]::StartNew()
 try{
  Section 'Export des resultats'
  Write-ExportProgress 'Export du rapport' 'Preparation des metadonnees...' 5 $timer
  $domainName=''
  try{$domainName=[string](Get-ADDomain @ADParams).DNSRoot}catch{}
  $report=[ordered]@{}
  $report.Tool='AD Advanced Audit'
  $report.Version=$Script:AuditVersion
  $report.StartedAt=[string]$Script:StartedAt
  $report.FinishedAt=[string](Get-Date)
  $report.Domain=$domainName
  $report.ReadOnly=$true
  $report.SelectedModules=[string[]]$Script:SelectedModules.ToArray()

  Write-ExportProgress 'Export du rapport' 'Normalisation des findings...' 10 $timer
  $report.Findings=ConvertTo-AuditSerializable ([object[]]$Script:Findings.ToArray())

  $keys=@($Script:Results.Keys)
  $serializableResults=[ordered]@{}
  $total=[Math]::Max(1,$keys.Count)
  for($i=0;$i -lt $keys.Count;$i++){
   $name=[string]$keys[$i]
   $percent=10+[int]((($i+1)/$total)*50)
   Write-ExportProgress 'Export du rapport' ('Normalisation: '+$name+' ('+($i+1)+'/'+$total+')') $percent $timer
   $serializableResults[$name]=ConvertTo-AuditSerializable $Script:Results[$name]
  }
  $report.Results=$serializableResults

  New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop|Out-Null
  $serializableReport=$report
  $needJson=($ExportFormat -eq 'JSON' -or $ExportFormat -eq 'Both')
  $needHtml=($ExportFormat -eq 'HTML' -or $ExportFormat -eq 'Both')
  $json=$null
  if($needJson -or $needHtml){
   Write-ExportProgress 'Export du rapport' 'Serialisation JSON finale...' 65 $timer
   $json=ConvertTo-Json -InputObject $serializableReport -Depth 20 -Compress
   Write-ExportProgress 'Export du rapport' ('JSON genere: '+([Math]::Round($json.Length/1MB,2))+' Mo') 80 $timer
  }
  if($needJson){
   $file=Join-Path $OutputPath 'AD-Audit.json'
   Write-ExportProgress 'Export du rapport' 'Ecriture du fichier JSON...' 88 $timer
   [System.IO.File]::WriteAllText([string]$file,[string]$json,(New-Object System.Text.UTF8Encoding($false)))
   $size=(Get-Item -LiteralPath $file -ErrorAction Stop).Length
   Ok ('Export JSON: '+$file+' ('+[Math]::Round($size/1MB,2)+' Mo)')
  }
  if($needHtml){
   $htmlFile=Join-Path $OutputPath 'AD-Audit.html'
   Write-ExportProgress 'Export du rapport' 'Generation HTML...' 94 $timer
   $safe=[System.Net.WebUtility]::HtmlEncode([string]$json)
   $html='<!doctype html><html><head><meta charset="utf-8"><title>AD Advanced Audit</title></head><body><h1>AD Advanced Audit</h1><pre>'+ $safe +'</pre></body></html>'
   [System.IO.File]::WriteAllText([string]$htmlFile,[string]$html,(New-Object System.Text.UTF8Encoding($false)))
   $size=(Get-Item -LiteralPath $htmlFile -ErrorAction Stop).Length
   Ok ('Export HTML: '+$htmlFile+' ('+[Math]::Round($size/1MB,2)+' Mo)')
  }
  Write-ExportProgress 'Export du rapport' ('Termine en '+(Format-Elapsed $timer)) 100 $timer
  if(-not $NoConsole){Write-Progress -Id 900 -Activity 'Export du rapport' -Completed}
  Ok ('Temps export: '+(Format-Elapsed $timer))
 }catch{
  if(-not $NoConsole){Write-Progress -Id 900 -Activity 'Export du rapport' -Completed}
  throw ('Erreur pendant l export: '+$_.Exception.Message+' | Ligne: '+$_.InvocationInfo.ScriptLineNumber+' | Commande: '+$_.InvocationInfo.Line.Trim())
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
  Users{AuditUsers;break};Groups{AuditGroups;break};Computers{AuditComputers;break};OUs{AuditOUs;break};GPOs{AuditGPOs;break};Domain{AuditDomain;break};DCs{AuditDCs;break};Sites{AuditSites;break};Trusts{AuditTrusts;break};DNS{AuditDNS;break};Delegation{AuditDelegation;break};SPNs{AuditSPNs;break};LAPS{AuditLAPS;break};Health{AuditHealth;break};Privileged{AuditPrivileged;break};Kerberos{AuditKerberos;break};PasswordPolicies{AuditPasswordPolicies;break};Security{AuditSecurity;break};Schema{AuditSchema;break};ADCS{AuditADCS;break};RecycleBin{AuditRecycleBin;break};AdminSDHolder{AuditAdminSDHolder;break};GPOAnalysis{AuditGPOAnalysis;break}
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
