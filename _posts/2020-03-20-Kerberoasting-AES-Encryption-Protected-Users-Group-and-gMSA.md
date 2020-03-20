---
layout: single
classes: wide
title:  "Kerberoasting: AES Encryption, Protected User Group and Group MSA"
---

# Kerberoasting: AES Encryption, Protected User Group and Group MSA



## Introduction



[Kerberoasting](https://attack.mitre.org/techniques/T1208/) is a type of attack targeting service accounts in Active Directory. It's a well-known attack in the field of Active Directory security. The Kerberos Network Authentication Service (V5) specification [[RFC4120]](https://tools.ietf.org/html/rfc4120) also considered this kind of attack in its security consideration with recommendation: 

`Because a client can request a ticket for any server principal and can attempt a brute force or dictionary attack against the server principal’s key using that ticket, it is strongly encouraged that keys be randomly generated (rather than generated from passwords) for any principals that are usable as the target principal for a KRB_TGS_REQ or KRB_AS_REQ messages.`



There are a lot of wonderful articles out there explaining Kerberoasting. I'll save some time and jump into the topic. Just a brief summary for Kerberoasting as introduction. In short, domain users are able to request kerberos service tickets for any entity with a Service Principal Names (SPN), which are normally associated with computer accounts (for example, CIFS, HOST and HTTP etc). An attacker can abuse this by requesting a service ticket for a specific user account that has SPN set, and brute force the ticket offline without triggering any alarms. The resulting password of this ticket is the credential of the user account.



A long and complex password for a service account with regular rotation is highly recommended to mitigate Kerberoasting. Also, I often hear people talking about enabling AES encryption to mitigate Kerbeorasting: "If we enforce service account to encrypt service ticket using AES256, the resulting ticket will not be cracked". Enabling AES encryption is also listed in MITRE ATT&CK technique https://attack.mitre.org/techniques/T1208/ :



![mire](/assets/img/mitre.png){: .align-center}



and OWASP document https://www.owasp.org/images/4/4a/OWASP_Frankfurt_-44_Kerberoasting.pdf :

<img src="/assets/img/owasp.png" alt="OWASP" style="zoom:24%;" />



as a valid mitigation method. Is that really true? Yes, and no.





## AES Encryption



Kerberoast generally targets user accounts with a SPN associated in Active Directory. This is because password for machine account is long and complex, it changes automatically every 30 days by default, which makes it hard to crack. On the contrary, user account password is set by human and tend to be less secure. In addition, the service ticket encryption level is determined by the value of an AD attribute `msDS-SupportedEncryptionTypes` during the TGS generation process, and this attribute has different default value set on machine account and user account.



[@harmj0y](https://twitter.com/harmj0y) has already discussed this AD attribute in his article [Kerberos Revisited](https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/). *By default, `msDS-SupportedEncryptionTypes` value for computer accounts is set to 0x1C (RC4_HMAC_MD5 | AES128_CTS_HMAC_SHA1_96 | AES256_CTS_HMAC_SHA1_96) according to [MS-KILE] 3.1.1.5. Service tickets for machines nearly always use AES256 as the highest mutually supported encryption type will be used in a Kerberos ticket exchange.*



For user accounts, the attribute is not defined or is set to 0. The KDC will need to check another attribute `userAccountControl` to determine which encryption method should be used. If the `USE_DES_KEY_ONLY` bit is in place, only DES will be used, otherwise DES and RC4 can be used. However, [the Windows 7, Windows 10, Windows Server 2008 R2 and later operating systems do not support DES by default](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos), which means RC4 will be used to encrypt the service ticket for modern systems by default.



By setting "This account supports Kerberos AES 128/256 bit encryption" in Active Directory Users and Computers user properties, `msDS-SupportedEncryptionTypes` will be changed to 0x18 (AES128_CTS_HMAC_SHA1_96 | AES256_CTS_HMAC_SHA1_96), which means this user account supports AES encryption only. However, harmj0y found that it is still possible to get RC4 encrypted ticket by specifying RC4 as the only supported encryption algorithm we support in the TGS request body. 



This is done by constructing SSPI/GSS-API for Kerberos authentication to get a usable TGT, then use this TGT to perfrom TGS-REQ and specify the encryption algorithm. The detailed information was explained in this [article](http://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/) using Rubes with the "/tgtdeleg" flag. 



To sum up, this is achieved by requesting a "fake" delegation for the CIFS service on the Domain Controller. The DC, which has unconstrained delegation enabled by default, is granted complete use of the client's identity. Thus, a forwarded TGT will be returned by the Ticket Granting Service (during the TGS exchange) for authentication forwarding. This new TGT resides in the authenticator of the resulting TGS ticket. The authenticator contains additional information in a ticket to prove that the message originated with the principal to whom the ticket was issued. The authenticator is encrypted with the session key and combined with the ticket to form an AP-REQ message. This information is then sent to the end server along with any additional application-specific information. We can simply extract this forwarded TGT using the cached session key. With this new TGT, we can request a service ticket for the target SPN and specify RC4 as the only supported encryption method.



During the generation process of TGS ticket, the domain controller looks up which account has the requested SPN registered in its servicePrincipalName field. The service ticket is encrypted with the hash of that account, using the highest level encryption key that both the client and service account support. However, this is not always true since accounts might not have AES keys in older domain that had domain functional level upgraded. Because of this, we can still get RC4 encrypted service ticket even though the user account has AES encryption enabled.



However, it works differently on Windows Server 2019 Domain Controller. It simply returns the service ticket encrypted by the highest level encryption key supported by the service account, no matter what level of encryption key that the client claims to support or what encryption type is in client's `msDS-SupportedEncryptionTypes` attribute. You will get AES256 encrypted ticket if the service account enables AES256 encryption even in 2008 Domain Functional Level on DC 2019. As a side note, I tried to compare user attributes applied on service account on DC 2016 and DC 2019 to find out what Microsoft changed, but didn't find anything interesting. Also, event logs are identical except the value of `Ticket Encryption Type`. I assume Microsoft changed something in kdcsvc.dll. Please let me know if you find anything interesting in that dll (or some other places) as I'm not good at reverse engineering. 



All in all, in a domain with Windows Server 2016 (or before) as the Domain Controller, enabling AES encryption does not mitigate Kerberoasting at all since attackers can simply specify RC4 as the only supported encryption method and ask for RC4 encrypted service tickets. For DC Windows Server 2019, enabling AES encyption does mitigate Kerberoasting by returning the highest level encryption key that the service account supports. However, [cracking AES encrypted ticket is still possible](https://github.com/hashcat/hashcat/pull/1955) and it's just a matter of time and effort (create/choose a reasonable dictionary). 





## Protected User Group



[Protected Users](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn466518(v%3Dws.11)) is a security group introduced in windows server 2012 R2 with additional protection against credential theft by not caching credentials in insecure ways. Basically, users added to this group cannot authenticate using NTLM, Digest, or CredSSP, cannot be delegated in Kerberos, cannot use DES or RC4 for Kerberos pre-authentication and the default TGT lifetime and renewal is reduced to 4 hours.



It is noteworthy that the encryption type for Kerberos protocol will be upgraded to AES for users in this security group. Does it mitigate Kerberoasting (TGS Exchange) if we add service account in the group? Let me first talk a little bit about ASREPRoasting since Microsoft only specify Kerberos pre-authentication (AS Exchange). 



Please read this amazing article about [ASREPRoasting](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) if you still don't know what it is. Just a quick reminder, ASREPRoast is an attack against users that do not require pre-authentication. The pre-authentication takes place during the AS exchange and occurs when the client first authenticates to the KDC. Per-auth data (encrypted timestamp) is required to sent to the KDC to ensure that the client who made the request is actually the principal named in the request. There's also a security consideration for pre-authentication in the [RFC4120] document:

`"Unless pre-authentication options are required by the policy of a realm, the KDC will not know whether a request for authentication succeeds. An attacker can request a reply with credentials for any principal. These credentials will likely not be of much use to the attacker unless it knows the client’s secret key, but the availability of the response encrypted in the client’s secret key provides the attacker with ciphertext that may be used to mount brute force or dictionary attacks to decrypt the credentials, by guessing the user’s password. For this reason it is strongly encouraged that Kerberos realms require the use of pre-authentication. Even with pre-authentication, attackers may try brute force or dictionary attacks against credentials that are observed by eavesdropping on the network."`



Let's take a look at the AS-REP when user does not require pre-authentication: 



<img src="/assets/img/as-rep.png" alt="as-rep" style="zoom:45%;" />



There are 6 items inside the as-rep message: pvno, msg-type, crealm, ticket and enc-part. Ticket and enc-part are particularly interesting to us. We can also notice that there's another enc-part inside the ticket. What's the difference between these two? 



Let's call the enc-part in the ticket "ENC1" and the second one "ENC2". For AS exchange, the response (AS-REP) contains a ticket for the client to present to the server (KDC), and a session key that will be shared by the client and the KDC. The session key and additional information are encrypted in the client’s secret key in ENC2. ENC2 also contains the nonce that must be matched with the nonce from the AS-REQ message. On the other hand, ENC1 in the ticket section holds the encrypted encoding of the EncTicketPart sequence (which contains flags, key, cname, authtime, authorization-data and etc). It is encrypted in the key shared by Kerberos and the end server (the server’s secret key, krbtgt key in this case). Now you should know which enc-part is needed for brute forcing user account password. // ENC2 ;)



By default, if we issue a runas command and login as a user that does not require pre-authentication, AES256 encrypted cipher will be returned as we support this encryption method:



<img src="/assets/img/etypeas-req.png" alt="etypeas-req" style="zoom:46%;" />



<img src="/assets/img/etypeas-rep.png" alt="etypeas-rep" style="zoom:46%;" />





However, by using [ASREPRoast.ps1](https://github.com/HarmJ0y/ASREPRoast), we can specify RC4 as the only supported encryption type and get a RC4 encrypted cipher to crack user password (See code snippet [here](https://github.com/HarmJ0y/ASREPRoast/blob/master/ASREPRoast.ps1#L553)). To my surprise, users in the Protected Users group are not well protected based on what Microsoft said: "The Kerberos protocol will not use the weaker DES or RC4 encryption types in the pre-authentication process": 



![rc4as-rep](/assets/img/rc4as-rep.png)



In addition, setting "This account supports Kerberos AES 128/256 bit encryption" does not change this behavior. 



Now it's time to go back to Kerberoasting and take a look at the TGS-REP when user account has SPN set but does not enable AES encryption: 



![tgs-rep](/assets/img/tgs-rep.png)



We can also observe two enc-part in the tgs-rep message. Again, let's call the enc-part in the ticket "ENC1" and the second one "ENC2". For TGS exchange, the response (TGS-REP) will include a ticket for the requested server or for a ticket granting server of an intermediate KDC to be contacted to obtain the requested ticket. The ciphertext part (ENC2) in the response is encrypted in the sub-session key from the Authenticator, if present, or in the session key from the TGT. It is not encrypted with the client’s secret key. On the other hand, ENC1 in the ticket section holds the encrypted encoding of the EncTicketPart sequence (which contains flags, key, cname, authtime, authorization-data and etc). It is encrypted with the key shared by Kerberos and the end server (the server’s secret key, the key of the user service account in this case). What is needed for Kerberoasting is ENC1 in the TGS-REP.



Service account in Protected Users group will still have RC4 encrypted service ticket returned:



![rc4kerberoast](/assets/img/rc4kerberoast.png)





Adding service user account in the Protected Users group does not mitigate Kerberoasting or ASREPRoasting at all! And warning from Microsoft:



![warning](/assets/img/warning.png)







## Group Managed Service Account (gMSA)





A [Managed Service Account (MSA)](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview) enables administrators to manage rights and permissions for services but with automatic password management. It can be used on a single server. A group Managed Service Account (gMSA) provides the same functions as managed service accounts but can be managed across multiple servers as in a server farm or a load-balancing arrangement. It provides a higher security option for non-interactive applications/services/processes/tasks that run automatically.



MSA can be used on more than one computer in the domain and MSA authentication information is stored on Domain Controllers. What's more, it has a system-managed password; it has automatic SPN support; it is tied to a specific computer; it can be assigned rights and permissions; it can not be used for interactive logon and it can not be locked out.



We can use Powershell AD module to create MSA. It would be better to first create a group to use and manage those service accounts:



```powershell

```

net group gMSAGroup /add /domain

net group gMSAGroup SERVER$ /add /domain

Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

New-ADServiceAccount gMSAccount -DNSHostName gMSAccount.testlab.local -PrincipalsAllowedToRetrieveManagedPassword gMSAGroup

```

```



You can specify server names or a group in which the servers are members. In this case, servers in gMSAGroup can use the service account and retrieve the password. After the account is created, installation for service account on each server is also needed:



```powershell

```

Install-WindowsFeature RSAT-AD-POWERSHELL

Set-ADServiceAccount -Identity gMSAccount -PrincipalsAllowedToRetrieveManagedPassword SERVER$

Install-ADServiceAccount gMSAccount

```

```



The sAMAccountName for this service account gMSAccount is `gMSAccount$` and the sAMAccountType is `MACHINE_ACCOUNT`. Just like the computer account, the password is random and complex and it changes every 30 days by default. In addition, the AD attribute `msDS-SupportedEncryptionTypes` also has the value of 0x1C (RC4_HMAC_MD5 | AES128_CTS_HMAC_SHA1_96 | AES256_CTS_HMAC_SHA1_96), which makes it a perfect mitigation method against Kerberoasting attack.







## Mitigation



The best mitigation for a Kerberoasting attack is to ensure the password for service account is long and complex with regular rotation. Using Group Managed Service Accounts is an effective way to enforce these constrains. 







## References/thanks

Thanks to the previously work done by [@harmj0y](https://twitter.com/harmj0y)  to help me get clear picture of Kerberoasting/ASREPRoasting attack. I always feel mind-freshing no matter how many times I read his blog posts. Also thanks [@_dirkjan](https://twitter.com/_dirkjan) for answering me questions and the BloodHoundGang community. A big thank you to my colleague [Constantin](https://twitter.com/_Herberos) who encouraged me, spent a lot of time to discuss with me and helped me.



[Machine Account Password Process](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/machine-account-password-process/ba-p/396026)



[Computer accounts encryption types from Microsoft](https://blogs.msdn.microsoft.com/openspecification/2009/09/12/msds-supportedencryptiontypes-episode-1-computer-accounts/)



[harmj0y's msDS-SupportedEncryptionTypes](http://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/)



[Rubeus's tgtdeleg internals](http://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/)



[Unconstrained delegation process explained by dirkjanm](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)















