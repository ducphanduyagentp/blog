---
title: "[CSAW CTF 17] RE100: Tablez"
date: 2017-10-22T16:34:52-04:00
Tags: ["CSAW CTF 17", "CTF", "reversing"]
Languages: ["Vietnamese", "English"]
---

[English version below](#english-tablez)
##### Vietnamese

```r
➜  file tablez 
tablez: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=72adea86090fb7deeb319e95681fd2c669dcc503, not stripped
```

Như vậy rất may mắn là binary này không bị stripped. Mở binary lên bằng r2 và xem qua hàm main thì có một số điểm đáng chú ý sau:

1. Dữ liệu được hardcoded từ `0x000008ba` tới `0x00000908`
2. Input được nhập vào biến `local_90h` ở `0x00000924`
3. Một vòng lặp gọi hàm `sym.get_tbl_entry` với tham số là input. Kết quả hàm này trả về được dùng để thay thế các ký tự trên input buffer.
4. input buffer sau khi bị biến đổi qua vòng lặp ở 3 sẽ được so sánh với dữ liệu hardcoded ở 1 bằng hàm strncmp (`0x000009f7`). `0x26` ký tự đầu tiên sẽ được so sánh.

Hàm `sym.get_tbl_entry` hoạt động như sau:

```C
for (int i = 0; i <= 0xfe; i++) {
  if (trans_tbl[i * 2] == input[i]) {
    return trans_tbl[i * 2 + 1];
  }
}
return 0;
```
với `trans_tbl` là một biến toàn cục đã được viết trước.

Như vậy, cách làm của mình như sau:

1. Lấy dữ liệu từ bản trans_tbl và dự liệu hardcode trong hàm main ra (mình gọi là password).
Để lấy dữ liệu từ bảng `obj.trans_tbl`: `pr 0xff@ obj.trans_tbl > data.bin`
(Print Raw 0xff bytes at address of obj.trans_tbl, redirect output to file data.bin)
2. Với mỗi ký tự trong password, bruteforce tất cả các ký tự ASCII để tìm một ký tự c sao cho c sau khi qua hàm `get_tbl_entry` sẽ biến đổi thành ký tự ở vị trí tương ứng trong password.

Solution:
```python
from pwn import *
from string import printable

def get_char(c):
    global trans_tbl
    for i in range(0xfe + 1):
        if trans_tbl[i * 2] == c:
            return trans_tbl[i * 2 + 1]
    return 0

trans_tbl = open('trans_tbl').read()
password = ''
password += p64(0xb1e711f59d73b327)
password += p64(0x30f4f9f9b399beb3)
password += p64(0xb19965237399711b)
password += p64(0xf9279923be111165)
password += p64(0x65059923)
password = password.strip('\x00')

flag = ''
for i in range(len(password)):
    for c in printable:
        if get_char(c) == password[i]:
            flag += c
            break
print flag
```

<a name="english-tablez"></a>

##### English

```r
➜  file tablez 
tablez: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=72adea86090fb7deeb319e95681fd2c669dcc503, not stripped
```

Fortunately, this binary is not stripped. After examining the main function, there are several noticeable points:

1. There is hardcoded data, seen from `0x000008ba` to `0x00000908`
2. The input buffer is `local_90h`, seen at `0x00000924`
3. A loop calls to `sym.get_tbl_entry` with the input buffer as the parameter. The returned results are used to replace data on the input buffer.
4. The input buffer after being transformed in #3 is compared to the hardcoded data in #1 using strncmp (`0x000009f7`). The first `0x26` characters are compared.

Pseudo code for `sym.get_tbl_entry`:

```C
for (int i = 0; i <= 0xfe; i++) {
  if (trans_tbl[i * 2] == input[i]) {
    return trans_tbl[i * 2 + 1];
  }
}
return 0;
```
with `trans_tbl` is an initialized global variable.

My solution:

1. Extract data from `trans_tbl` and the hardcoded data at the beginning of main (called password).
To extract data from `obj.trans_tbl` using r2: `pr 0xff@ obj.trans_tbl > data.bin`
(Print Raw 0xff bytes at address of obj.trans_tbl, redirect output to file data.bin)
2. For each character in the password, bruteforce all ASCII characters to find a character c such that c after being transformed by `get_tbl_entry` will be the corressponding character in the password.

Solution:
```python
from pwn import *
from string import printable

def get_char(c):
    global trans_tbl
    for i in range(0xfe + 1):
        if trans_tbl[i * 2] == c:
            return trans_tbl[i * 2 + 1]
    return 0

trans_tbl = open('trans_tbl').read()
password = ''
password += p64(0xb1e711f59d73b327)
password += p64(0x30f4f9f9b399beb3)
password += p64(0xb19965237399711b)
password += p64(0xf9279923be111165)
password += p64(0x65059923)
password = password.strip('\x00')

flag = ''
for i in range(len(password)):
    for c in printable:
        if get_char(c) == password[i]:
            flag += c
            break
print flag
```