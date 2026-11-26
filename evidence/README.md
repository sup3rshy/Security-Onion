# Bằng chứng thực nghiệm 2026-11-25 (VMware Workstation)

Sinh ra từ phiên chạy 6 kịch bản ngày 2026-11-25. Nội dung diễn giải nằm ở
[../scenarios_report.md](../scenarios_report.md) mục **§7**.

| File | Kịch bản | Dùng để chứng minh |
|---|---|---|
| `s1-scan.txt` | 1 | Kết quả nmap: 12 cổng mở, 988 closed (định dạng text của nmap) |
| `s1-scan.gnmap` | 1 | Cùng lần quét, định dạng grep-able |
| `s1-zeek-conn-scan.json` | 1 | Truy vấn `zeek.conn` tới 192.168.100.188 (Hunt tương đương) |
| `s1-suricata-alerts.json` | 1 | Alert Suricata trong cửa sổ thử nghiệm + tên rule |
| `s2-zeek-ssh.json` | 2 | `zeek.ssh` metadata các lần đăng nhập SSH thất bại |
| `s2-msf-authlog-failed.txt` | 2 | Trích `/var/log/auth.log` trên target (host visibility) |
| `s3-zeek-http-markers.json` | 3 | `zeek.http`: method/URI/UA/status của 2 request có marker |
| `s5-zeek-file.json` | 5 | `zeek.file`: MIME, size, MD5/SHA1, fuid khớp với `zeek.http` |
| `s6-zeek-http-canary.json` | 6 | Request của attacker vào honeypot (port 8081) |

## Hai file không nằm trong git

`.gitignore` của repo chặn `*.pcap` và `*.log`, nên hai artifact sau **chỉ tồn tại ở máy local**:

| File | Kích thước | SHA256 |
|---|---|---|
| `s1-capture.pcap` | 176.172 byte (1.993 packet) | `aaca089483749818e50155734f9aeda12222587e2c6b966dfcbda902e0a1fb22` |
| `scenario2-auth-attack.log` | 915 byte (log do script s2 sinh ra) | `82e3d46aaea8ec5f0da9962a9de80358a6595a868898516a56bf3bc7af56ac84` |

Muốn đưa vào git thì phải `git add -f`, hoặc chép sang máy khác trước khi dọn.

Cách tạo lại:

- **pcap**: trên Security Onion, chạy `sudo tcpdump -nn -i bond0 -w s1-capture.pcap 'host 192.168.100.188'` rồi quét lại từ Kali.
- **log s2**: chạy `./src/scenarios/s2/auth_attack_simulation.sh 192.168.100.188 labuser` trên Kali, log được ghi vào `scenario2-auth-attack.log` tại thư mục hiện hành.

## Ghi chú về giá trị bằng chứng

- Không có alert Suricata kiểu "nmap SYN scan" trong ruleset đang bật; kết luận scan dựa trên số cổng đích khác nhau trong `zeek.conn` và SYN trong pcap.
- Zeek tính MD5/SHA1 cho `zeek.file`, không tính SHA256; hash SHA256 trong báo cáo lấy từ host.
