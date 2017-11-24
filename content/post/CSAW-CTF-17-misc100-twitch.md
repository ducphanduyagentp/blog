---
title: "[CSAW CTF 17] Misc100: Twitch"
date: 2017-10-22T16:34:38-04:00
Tags: ["csaw-ctf-17"]
Categories: ["CTF", "reversing", "pwn", "misc"]
Languages: ["Vietnamese", "English"]
---

[English version here](#english-twitch)
##### Vietnamese

Bài này là bài bựa nhất trong cả đề. Đại khái là họ stream một cái shell lên twitch. Để điều khiển shell đó thì người xem twitch sẽ vote phím nào được ấn trên bàn phím bằng cách gõ vào phần chat. Để lấy được flag bài này thì số người đó phải exploit 1 binary bị buffer overflow. Mình thì không rảnh nhảy vào vote nên chỉ xem xong cướp flag thôi =)) Điều bựa là mỗi khi flag được lấy ra thành công thì sau vài phút, cái máy tính được stream sẽ tự động reboot và ai không lấy kịp flag thì lại ngồi chờ =))
![misc100](img/csaw-ctf-qualification-2017/misc100.jpg)

<a name="english-twitch"></a>

##### English

This is quite a funny challenge. All the players need to exploit a binary and the shell is streamed on twitch and controlled via a twitch chat. All the players need to vote for the character that they want to type in the shell. To get the flag, you need to be there at the right moment since the machine which contains the binary and the shell reboots whenever the flag is successfully printed out.
