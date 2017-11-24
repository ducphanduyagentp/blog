---
title: "[CSAW CTF 17] Forensics 200: Bestrouter"
date: 2017-10-22T16:23:20-04:00
Tags: ["ctf", "forensics", "csaw-ctf-17"]
Categories: ["CTF"]
---

Bài này khá vớ vẩn. Download file đính kèm về giải nén ra thì ta sẽ được một file `.img`, là một file image của rasberry pi. Mình dùng lệnh sau để mount file này trên linux, từ đó sẽ đọc được dữ liệu trong file như cấu trúc của một linux filesystem thông thường:

```r
sudo mount disk.img ./mnt
```

(Lúc làm bài này mình làm theo hướng dẫn ở [đây](https://www.linuxquestions.org/questions/linux-general-1/how-to-mount-img-file-882386/#post4365399), thi xong mình xóa xừ nó file kia đi rồi nên không nhớ cụ thể câu lệnh là gì nữa :P )

Mở lên và truy cập vào thư mục `/var/www/html` sẽ thấy được mã nguồn của trang web cần đăng nhập: `http://forensics.chal.csaw.io:3287/`
Trên windows, file này có thể được mở bằng phần mềm chuyên dụng cho forensics như Autopsy. Bài này do ngu người không để ý có cái trang web kia nên mình tìm thấy mật khẩu rồi mãi không biết dùng làm gì :D