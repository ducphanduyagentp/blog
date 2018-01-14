---
title: "[CSAW CTF 17] RE400: Realism"
date: 2017-10-22T15:18:22-04:00
Tags: ["csaw-ctf-17"]
Categories: ["CTF", "reversing"]
Language: ["English", "Vietnamese"]
Draft: true
---

[English version below](#english-realism)

##### Vietnamese
Đây là lần đầu tiên trong 1 CTF mà mình dám động tới một bài 400. Trước khi được thông não, mình thường còn chẳng xem đề bài mấy bài này vì nghĩ chỉ có rất khủng mới làm được. Lần này khi mở lên thấy bài này hơn 30 người làm được sau ngày đầu tiên, mình nghĩ rằng đây không phải bài khó nên quyết định thử sức. Đây là một quyết định vừa đúng lại vừa có phần hơi ngu người vì làm mình bỏ lỡ mất bài pwn 200 khá ngon ăn.

```r
➜  file main.bin
main.bin: DOS/MBR boot sector
```

Sau một hồi tìm hiểu, mình đã chạy được file này. Kết quả ra như sau:

![QEMU-Run](/img/csaw-ctf-qualification-2017/re400-1.png)

Đây là lần đầu tiên mình reverse/debug 1 MBR. Cách cài đặt môi trường để debug như sau:

Link tham khảo: https://rwmj.wordpress.com/2011/10/12/tip-debugging-the-early-boot-process-with-qemu-and-gdb/

1. Cài đặt qemu-system-i386
2. Chạy MBR và debug với GDB như sau:
  1. `qemu-system-i386 -s -S -drive format=raw,file=main.bin`: Lệnh này load file MBR nhưng không chạy CPU, đồng thời mở 1 gdbserver tại port 1234 ở localhost để có thể dùng gdb debug
  2. Vào gdb:
    1. `target remote localhost:1234`: Kết nối để gdbserver được khởi tạo ở bước trên
    2. 