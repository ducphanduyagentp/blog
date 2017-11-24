---
title: "[CSAW CTF 17] RE100: Tablez"
date: 2017-10-22T16:34:52-04:00
draft: true
---

```r
➜  tablez git:(master) ✗ file tablez 
tablez: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=72adea86090fb7deeb319e95681fd2c669dcc503, not stripped
```
Như vậy rất may mắn là binary này không bị stripped. Mở binary lên bằng r2 và xem hàm main thì thấy 1 đoạn khá đáng ngờ
<!-- ![re100-1](/img/csaw-ctf-qualification-2017/re100-1.png) -->
```python
|           0x000008ba      48b827b3739d.  movabs rax, -0x4e18ee0a628c4cd9
|           0x000008c4      48bab3be99b3.  movabs rdx, 0x30f4f9f9b399beb3
|           0x000008ce      48898540ffff.  mov qword [local_c0h], rax
|           0x000008d5      48899548ffff.  mov qword [local_b8h], rdx
|           0x000008dc      48b81b719973.  movabs rax, -0x4e669adc8c668ee5
|           0x000008e6      48ba651111be.  movabs rdx, -0x6d866dc41eeee9b
|           0x000008f0      48898550ffff.  mov qword [local_b0h], rax
|           0x000008f7      48899558ffff.  mov qword [local_a8h], rdx
|           0x000008fe      c78560ffffff.  mov dword [local_a0h], 0x65059923
|           0x00000908      66c78564ffff.  mov word [local_9ch], 0xce
```

Đoạn mã trên thực hiện copy hàng loạt các bytes được hard-code lên buffer bắt đầu từ local_c0h. Lui xuống dưới 1 đoạn thì thấy input nhập vào được so sánh với chính buffer này.

```python
0x000009de      488d8d40ffff.  lea rcx, qword [local_c0h]
0x000009e5      488d8570ffff.  lea rax, qword [local_90h]
0x000009ec      ba26000000     mov edx, 0x26               ; '&'
0x000009f1      4889ce         mov rsi, rcx
0x000009f4      4889c7         mov rdi, rax
0x000009f7      e8f4fcffff     call sym.imp.strncmp        ; int strncmp(const char *s1, const char *s2, size_t n)
0x000009fc      85c0           test eax, eax
0x000009fe      7513           jne 0xa13
0x00000a00      488d3dda0000.  lea rdi, qword str.CORRECT__3 ; 0xae1 ; "CORRECT <3"
0x00000a07      e8f4fcffff     call sym.imp.puts           ; int puts(const char *s)
```
<!-- ![re100-2](/img/csaw-ctf-qualification-2017/re100-2.png) -->

Trong quá trình làm bài, mình có sử dụng tính năng rename biến của r2 để việc theo dõi luồng thực thi được dễ dàng hơn, ví dụ như:

```r
[0x000008a0]> s main
[0x000008a0]> afvn local_90h input_buffer # Rename local_90h to input_buffer
[0x000008a0]> afvn local_c0h to_cmp # Rename local_c0h to to_cmp
[0x000008a0]> pdf
```

Khi in lại hàm main ra thì sẽ thấy như sau:
```python
|      |`-> 0x000009de      488d8d40ffff.  lea rcx, qword [to_cmp]
|      |    0x000009e5      488d8570ffff.  lea rax, qword [input_buffer]
|      |    0x000009ec      ba26000000     mov edx, 0x26               ; '&'
|      |    0x000009f1      4889ce         mov rsi, rcx
|      |    0x000009f4      4889c7         mov rdi, rax
|      |    0x000009f7      e8f4fcffff     call sym.imp.strncmp        ; int strncmp(const char *s1, const char *s2, size_t n)
|      |    0x000009fc      85c0           test eax, eax
|      |,=< 0x000009fe      7513           jne 0xa13
|      ||   0x00000a00      488d3dda0000.  lea rdi, qword str.CORRECT__3 ; 0xae1 ; "CORRECT <3"
|      ||   0x00000a07      e8f4fcffff     call sym.imp.puts           ; int puts(const char *s)
```
<!-- ![re100-3](/img/csaw-ctf-qualification-2017/re100-3.png) -->