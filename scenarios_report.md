# Báo cáo và handoff các scenarios — Security Onion

## 1. Phạm vi và trạng thái

Tài liệu đi kèm `Readme.md`, dùng để ghi nhận kết quả thực nghiệm và hướng dẫn người tiếp nhận tiếp tục triển khai.

**Chỉ thực hiện kiểm thử trên các máy và mạng lab thuộc quyền quản lý.** Không quét mạng bên ngoài hoặc chạy script khai thác.

| Scenario | Nội dung | Trạng thái (sau phiên 2026-11-25, VMware) |
|---|---|---|
| 1 | Network Scanning | ✅ Đã chạy lại đầy đủ trên VMware: 12 cổng mở, `zeek.conn` 1001 cổng đích khác nhau, PCAP 1.993 packet, Suricata có alert liên quan scan (ET SCAN Potential SSH Scan). Chi tiết §7.1 |
| 2 | Authentication Attack Simulation | ✅ 6 lần sai mật khẩu SSH từ `192.168.100.50`; Zeek `zeek.ssh` + auth.log trên target đều xác nhận. Chi tiết §7.2 |
| 3 | Suspicious Web Activity | ✅ `zeek.http` ghi đủ method/URI/User-Agent/status của cả request 404 có marker và request UA `SO-LAB-TEST`. Chi tiết §7.3 |
| 4 | Endpoint Detection | ✅ Đã enroll Elastic Agent (host `kali`, policy `endpoints-initial`) và có 8.237 process event trong Hunt, gồm marker `SO-LAB-POWERSHELL` và chuỗi `base64 -d &#124; bash`; phải sửa 4 lỗi firewall/DNS/CA mới thông. Chi tiết §7.4 |
| 5 | File Transfer + PCAP Investigation | ✅ Truyền `lab-test.txt` qua HTTP, hash hai đầu khớp, `zeek.http` + `zeek.file` có bằng chứng. Chi tiết §7.5 |
| 6 | Honeypot | ✅ OpenCanary (SSH 2222 + HTTP 8081) bị kết nối từ `192.168.100.188`; log canary + `zeek.http` xác nhận. Chi tiết §7.6 |

> Phiên 2026-11-25 chạy trên **VMware Workstation** thay cho KVM; môi trường, IP và sai khác so với tài liệu cũ ghi ở §7.0. Bằng chứng thô lưu trong `evidence/`.

Các mục hướng dẫn bên dưới không đồng nghĩa với việc đã thực hiện thành công. Chỉ đánh dấu hoàn thành khi có bằng chứng tương ứng.

> **Runbook ngắn cho cả 6 scenario:** xem [`scenarios_step_by_step.md`](scenarios_step_by_step.md).

---

## 2. Scenario 1 — Network Scanning

### 2.1. Mục tiêu

Chứng minh analyst có thể nhận diện hành vi quét dịch vụ mạng và điều tra theo chuỗi:

```text
Nmap scan → Suricata alert → Zeek connection metadata → PCAP → Case
```

**MITRE ATT&CK:** T1046 — Network Service Scanning.

Trong phiên thực nghiệm này, đã chứng minh được:

```text
Nmap scan → traffic được mirror tới sensor → Zeek connection logs
```

Các phần Suricata alert, PCAP trong SOC và Case còn cần hoàn thiện.

### 2.2. Mô hình thực nghiệm thực tế

Để giảm số lượng VM, dùng Kali trên máy host làm máy quét và chính IP quản lý Security Onion làm mục tiêu.

```text
Kali host: 192.168.122.1
         │ Nmap TCP scan
         ▼
Security Onion management: 192.168.122.10
         │
         │ Host KVM mirror traffic hai chiều
         ▼
Security Onion sniffing NIC: enp7s0 → bond0 → Suricata / Zeek
```

> Đây là mô hình demo tối giản: sensor đồng thời là mục tiêu. Không phải mô hình doanh nghiệp trong `Readme.md`, vốn dùng mục tiêu riêng và SPAN/TAP. Khi báo cáo phải ghi rõ khác biệt này.

| Thành phần | Giá trị trong phiên thực nghiệm |
|---|---|
| Hypervisor | QEMU/KVM, virt-manager |
| Tên domain libvirt | `rocky9` — tên VM, không dùng tên này để suy luận hệ điều hành |
| Phiên bản trong Setup | Security Onion 3.3.0 |
| Kiểu triển khai | Standalone |
| Máy quét | Kali host |
| IP nguồn thấy trong tcpdump/Zeek | `192.168.122.1` |
| Management NIC trong VM | `enp1s0`, IP `192.168.122.10/24` |
| MAC management | `52:54:00:6a:e7:91` |
| Sniffing NIC trong VM | `enp7s0`, không có IP; nằm trong capture bond |
| MAC sniffing | `52:54:00:48:04:63` |
| Mạng management | `default`, NAT, bridge `virbr0`, gateway `192.168.122.1` |
| Mạng sniffing | `lab-net`, isolated, `192.168.100.0/24`, bridge `virbr1` |
| Management tap trên host tại thời điểm thực hiện | `vnet14` |
| Sniffing tap trên host tại thời điểm thực hiện | `vnet15` |

**Quan trọng:** `vnet14` và `vnet15` có thể thay đổi sau khi VM khởi động lại. Luôn xác định lại bằng MAC trước khi dùng lệnh mirror.

## 3. Hướng dẫn tái hiện Scenario 1 từng bước

### Bước 1 — Kiểm tra dịch vụ và mạng

**Trong VM Security Onion:**

```bash
ip -br addr
sudo so-status
```

Điều kiện để tiếp tục:
- `enp1s0` có `192.168.122.10/24`.
- NIC sniffing `enp7s0` không có IP.
- Suricata và Zeek hoạt động; SOC truy cập được qua `https://192.168.122.10` (trên Security Onion 3.3, quản lý quyền truy cập qua `sudo so-firewall includehost analyst <IP_or_CIDR> --apply`).

**Trên host Kali:**

```bash
sudo virsh domiflist rocky9
```

Đối chiếu theo MAC, không đoán theo thứ tự dòng:

```text
52:54:00:6a:e7:91 → management tap
52:54:00:48:04:63 → sniffing tap
```

Các lệnh dưới giả định kết quả vẫn là management `vnet14`, sniffing `vnet15`. Nếu khác, thay đúng tên trong mọi lệnh.

### Bước 2 — Mirror traffic trên host

Chỉ nối NIC sniffing vào một mạng ảo không tự làm nó nhìn thấy toàn bộ unicast traffic. Bài này copy traffic trên management tap tới sniffing tap.

**Kiểm tra hiện trạng trước:**

```bash
sudo tc qdisc show dev vnet14
sudo tc -s filter show dev vnet14 ingress
sudo tc -s filter show dev vnet14 egress
```

Nếu chưa có `clsact`, tạo:

```bash
sudo tc qdisc add dev vnet14 clsact
```

Nếu báo `File exists`, kiểm tra có đúng `clsact` không; không xóa qdisc hoặc filter khác để ép lệnh chạy.

Nếu chưa có hai filter của bài lab, tạo từng lệnh trên một dòng:

```bash
sudo tc filter add dev vnet14 ingress pref 49150 matchall action mirred egress mirror dev vnet15
sudo tc filter add dev vnet14 egress pref 49150 matchall action mirred egress mirror dev vnet15
```

Nếu priority `49150` đã được dùng bởi cấu hình khác, dừng và chọn priority trống; không ghi đè filter của người khác.

Kiểm tra lại:

```bash
sudo tc -s filter show dev vnet14 ingress
sudo tc -s filter show dev vnet14 egress
```

Mong đợi: thấy `matchall`, action mirror tới `vnet15`; sau khi có traffic, bộ đếm packet/byte tăng.

**Giới hạn:** mirror này copy cả traffic quản lý, đăng nhập SOC và TLS. Chỉ bật tạm trong lab, bảo vệ PCAP như dữ liệu nhạy cảm. Filter không được đảm bảo tồn tại sau reboot hoặc tái tạo tap.

### Bước 3 — Xác nhận sensor thấy scan

**Trong VM Security Onion, chạy trước:**

```bash
sudo timeout 60 tcpdump -nn -i enp7s0 'host 192.168.122.10 and tcp and portrange 1-100'
```

Chờ dòng `listening on enp7s0`, rồi chạy bước 4 trên host trong khoảng 60 giây đó.

Mong đợi:
- Nguồn `192.168.122.1`.
- Đích `192.168.122.10`.
- Nhiều cổng đích từ 1 tới 100.
- `Flags [S]` tương ứng TCP SYN.

Chỉ nhìn thấy traffic HTTPS của SOC không đủ xác minh scan. `tcpdump` thấy packet cũng chưa chứng minh pipeline Zeek, alert hay full packet capture hoạt động; cần kiểm tra riêng các bước sau.

### Bước 4 — Chạy scan có giới hạn

**Trên host Kali, trong thư mục lưu bằng chứng:**

```bash
date -Is
sudo nmap -sS -Pn -p 1-100 -T3 --reason 192.168.122.10 -oN scenario1-scan.txt
```

| Tùy chọn | Ý nghĩa |
|---|---|
| `sudo`, `-sS` | TCP SYN scan, cần quyền raw packet |
| `-Pn` | Không dùng host discovery thông thường để quyết định bỏ qua mục tiêu; vẫn có thể có ARP trên LAN |
| `-p 1-100` | Chỉ quét 100 cổng đầu |
| `-T3` | Timing mức mặc định/normal |
| `--reason` | Hiển thị lý do phân loại cổng |
| `-oN` | Lưu kết quả text vào thư mục hiện tại trên host |

Không có script khai thác hoặc đăng nhập thử trong lệnh này.

Xem kết quả:

```bash
cat scenario1-scan.txt
```

File Nmap không được gửi vào Security Onion. Sensor phân tích traffic được mirror.

### Bước 5 — Hunt dữ liệu Zeek

1. Đăng nhập SOC, mở **Hunt**.
2. Chọn thời gian bao phủ lần scan. Nếu xem lại dữ liệu cũ, dùng khoảng thời gian tuyệt đối thay vì `Last 15 minutes`.
3. Thay query hiện tại bằng:

```text
event.dataset:"zeek.conn" AND source.ip:192.168.122.1 AND destination.ip:192.168.122.10 AND destination.port:[1 TO 100]
```

4. Nhấn Enter; chờ pipeline ingest nếu vừa scan, sau đó refresh.
5. Hiển thị các cột timestamp, dataset, source IP/port, destination IP/port, transport.
6. Mở một event bằng dấu `>` và ghi lại chi tiết.

Mong đợi: nhiều kết nối TCP tới nhiều cổng trong khoảng thời gian rất ngắn.

Nếu trường có mặt, kiểm tra `zeek.conn.conn_state`. `S0` thường là thấy kết nối khởi đầu nhưng không thấy phản hồi; không tự kết luận cổng đóng. Mất packet hoặc mirror thiếu một chiều cũng có thể ảnh hưởng trạng thái.

**Lưu ý:** biểu tượng tam giác xanh trong Hunt không phải bằng chứng đã có alert Suricata.

---

---

# 7. Kết quả thực nghiệm 2026-11-25 — VMware Workstation

## 7.0. Môi trường thực tế và sai khác so với tài liệu cũ

| Thành phần | Giá trị thực tế |
|---|---|
| Hypervisor | VMware Workstation (host Windows), điều khiển từ WSL2 |
| Security Onion | 3.3.0, Oracle Linux 9.8, kernel 6.12 UEK, standalone |
| NIC quản lý SO | `ens160` — 192.168.182.10/24 (VMnet8 NAT), GW 192.168.182.2 |
| NIC sniffing SO | `ens224` (KHÔNG IP) → enslaved vào `bond0`, `PROMISC` |
| Attacker | VM Kali `192.168.100.50/24` (eth1 = VMnet2), eth0 = VMnet8 192.168.182.60 |
| Target | Metasploitable 2 `192.168.100.188/24` (eth0 = VMnet2) |
| Mạng lab | VMnet2 (custom, không có adapter trên host) |
| Mạng quản trị | VMnet8 (NAT, 192.168.182.0/24) |

Sai khác cần ghi rõ khi báo cáo:

1. **Tên NIC đổi** so với tài liệu KVM: `ens33/ens34` → `ens160/ens224`; NIC sniffing nằm trong `bond0` (đúng mô hình capture bond của SO).
2. **Không cần `tc mirred` trên VMware.** VMnet2 hoạt động như hub ảo: NIC `ens224` ở chế độ `PROMISC` nhận được toàn bộ unicast giữa hai VM cùng vnet. Đã kiểm chứng bằng `tcpdump -i bond0` thấy ARP/ICMP/HTTP/SSH giữa .50 và .188.
3. **Không dùng DHCP cho mạng lab.** VMnet2 có DHCP riêng ở dải `10.81.23.0/24`, nên hai máy lab đặt IP tĩnh `192.168.100.0/24` để khớp tài liệu (cùng L2, khác subnet DHCP không ảnh hưởng).
4. **Attacker là VM Kali**, không phải máy host, nên toàn bộ traffic đi qua VMnet2 và sensor nhìn thấy.
5. **Bằng chứng Hunt lấy trực tiếp từ Elasticsearch** bằng `so-elasticsearch-query` trên SO (cùng index/pipeline mà giao diện Hunt dùng), không phụ thuộc thao tác tay trên UI. File JSON thô lưu ở `evidence/`.

## 7.1. Scenario 1 — Network Scanning (T1046) ✅

**Lệnh chạy (Kali):**

```bash
date -Is
sudo nmap -sS -Pn -p 1-1000 -T3 --reason 192.168.100.188 -oN s1-scan.txt -oG s1-scan.gnmap
```

**Bước 0 — xác nhận sensor thấy traffic trước khi scan:** `tcpdump -nn -i bond0 'host 192.168.100.188'` thấy ARP, ICMP và TCP SYN của kết nối thử.

**Kết quả nmap:** host up (arp-response), **12 cổng mở** — 21/ftp, 22/ssh, 23/telnet, 25/smtp, 53/domain, 80/http, 111/rpcbind, 139/netbios-ssn, 445/microsoft-ds, 512/exec, 513/login, 514/shell; 988 cổng closed; thời gian quét 0,47 s.

**Bằng chứng từng lớp:**

| Lớp | Kết quả |
|---|---|
| PCAP (`s1-capture.pcap`) | 1.993 packet trong cửa sổ quét, thấy SYN tới nhiều cổng liên tiếp |
| Zeek `zeek.conn` | **1.031** bản ghi tới 192.168.100.188 (180 phút); trong cửa sổ 25 phút: **904** conn, **1.001 cổng đích khác nhau**, toàn bộ từ `192.168.100.50` |
| Suricata | 17 alert/180 phút: `GPL ICMP PING *NIX` ×5, `ET HUNTING curl User-Agent to Dotted Quad` ×2, **`ET SCAN Potential SSH Scan`** ×1, `ET SCAN Potential SSH Scan OUTBOUND` ×1, `ET INFO Python SimpleHTTP ServerBanner` ×1 |

**Kết luận đúng bản chất:** **không có** signature dạng "nmap SYN scan" trong ruleset đang bật, nên không được ghi "Suricata phát hiện nmap". Bằng chứng quyết định là **Zeek conn với 1.001 cổng đích khác nhau trong vài giây** + PCAP có SYN tương ứng. Alert `ET SCAN Potential SSH Scan` chỉ là tín hiệu phụ (nhiều lần chạm cổng 22), không phải kết luận của scenario.

**Artifact:** `evidence/s1-scan.txt`, `s1-scan.gnmap`, `s1-capture.pcap`, `s1-zeek-conn-scan.json`, `s1-suricata-alerts.json`.

## 7.2. Scenario 2 — SSH Authentication Attack (T1110.001) ✅

**Thực hiện:** dùng chính script của đồ án `src/scenarios/s2/auth_attack_simulation.sh 192.168.100.188 labuser` trên Kali. Hydra 9.7 **không dùng được** (OpenSSH 4.7p1 chỉ offer `hmac-md5/hmac-sha1`, client chỉ có `hmac-sha2-*` → `kex error: no match for method mac`). Script có fallback **paramiko** nên vẫn chạy được 6 lần thử.

**Kết quả:** 6/6 thất bại (123456, password, admin123, toor2024, letmein, wrongpass1).

**Bằng chứng 2 phía:**

| Nguồn | Bằng chứng |
|---|---|
| Mạng (Zeek) | `zeek.ssh`: 22 bản ghi, toàn bộ `source.ip = 192.168.100.50`, `destination.ip = 192.168.100.188`; `zeek.conn` tới cổng 22 tăng tương ứng |
| Host (target) | `/var/log/auth.log`: **6 dòng** `Failed password for labuser from 192.168.100.50 port ... ssh2` (02:49:36 → 02:49:47) kèm `pam_unix(sshd:auth): authentication failure` |

**Điểm nhấn giữ nguyên giá trị:** Zeek chỉ thấy kết nối + banner, **không giải mã được payload**; muốn biết username bị dò và kết quả đăng nhập phải có auth.log của endpoint — đúng luận điểm §2.4.

**Artifact:** `evidence/scenario2-auth-attack.log`, `s2-zeek-ssh.json`, `s2-msf-authlog-failed.txt`.

## 7.3. Scenario 3 — Suspicious Web Activity ✅

**Thực hiện (Kali → Apache 2.2.8 trên Metasploitable):**

```bash
curl -i "http://192.168.100.188/does-not-exist?lab=SO-SCENARIO3"
curl -i -A "SO-LAB-TEST" "http://192.168.100.188/"
```

**Bằng chứng `zeek.http` (14:04:42 UTC):**

| method | uri | user-agent | status | virtual_host |
|---|---|---|---|---|
| GET | `/does-not-exist?lab=SO-SCENARIO3` | `curl/8.20.0` | 404 | 192.168.100.188 |
| GET | `/` | `SO-LAB-TEST` | 200 | 192.168.100.188 |

Analyst trả lời được đủ: **ai gọi, gọi cái gì, bằng UA nào, kết quả ra sao** — chỉ từ metadata, không cần đọc payload. Marker vô hại, không có khai thác SQLi/XSS.

**Artifact:** `evidence/s3-zeek-http-markers.json`.

## 7.4. Scenario 4 — Endpoint Detection (T1059.001 / T1082) ✅

**Kết quả:** Elastic Agent đã cài trên endpoint, **enroll vào Fleet thành công** và **telemetry process chảy về SOC** — chuỗi "Agent → Fleet → Elasticsearch → Hunt" đã thông suốt và có bằng chứng.

| Thành phần | Giá trị |
|---|---|
| Agent ID | `fafbd3a0-fb37-47ed-b9e8-a024432c2db3` |
| Host | `kali` (Kali GNU/Linux 2026.2, kernel 6.19.14) |
| Agent version | 9.4.5 (stack 9.4.5) |
| Agent policy | `endpoints-initial` |
| Trạng thái | `elastic-agent: HEALTHY Running`, `fleet: Connected` |
| Dữ liệu | 8.237 `endpoint.events.process` + `endpoint.events.file/network` trong 60 phút |

**Bốn lỗi thật phải sửa mới chạy được** (mỗi lỗi đều đã kiểm chứng, không phải suy đoán):

| # | Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|---|
| 1 | `curl https://<SO>:8220` → `http=000` | `DOCKER-USER` của SO chỉ mở 80/443 cho hostgroup `analyst`; 8220 thuộc hostgroup **`elastic_agent_endpoint`** (role `eval`) | `sudo so-firewall includehost elastic_agent_endpoint 192.168.182.0/24 --apply` |
| 2 | Port 9200 đóng từ endpoint | Output của agent đi thẳng **Elasticsearch:9200**, port này chỉ mở cho hostgroup `eval` | `sudo so-firewall includehost eval 192.168.182.0/24 --apply` |
| 3 | `lookup shyonion on 8.8.8.8:53: no such host` | Policy đẩy output theo **hostname** `shyonion`, endpoint không có DNS nội bộ | thêm `192.168.182.10 shyonion` vào `/etc/hosts` của endpoint |
| 4 | `x509: certificate signed by unknown authority` | CA tự ký của SO không có trong trust store của endpoint | chép `/etc/pki/ca.crt` của SO vào `/usr/local/share/ca-certificates/` rồi `update-ca-certificates` |

**Bằng chứng Hunt (process telemetry):**

| Thời điểm (UTC) | process.name | process.command_line | parent |
|---|---|---|---|
| 01:09:16.32 | `bash` | `bash -c echo SO-LAB-POWERSHELL-MARKER-2026` | bash |
| 01:09:16.37 | `base64` | `base64` | bash |
| 01:09:16.38 | `bash` | `bash -c echo ZWNobyBTTy1MQUItQkFTRTY0LURFQ09ERUQ= | base64 -d | bash` | bash |
| 01:18:11.22 | `bash` | `bash -c echo SO-LAB-POWERSHELL-MARKER-2026` | bash |

Cùng bản ghi còn có `user.name`, `host.name`, `process.hash.sha256` — analyst có đủ **user, tiến trình cha, hash, command line nguyên bản**, đúng thứ mà Zeek/Suricata không thể thấy khi traffic đã mã hoá.

**Sai khác so với scenario gốc (Windows + Sysmon):** dùng endpoint **Linux** thay vì Windows vì VM `Windows 10 x64` trong máy không có mật khẩu/quyền admin để cài Sysmon. Luận điểm kiến trúc giữ nguyên: chỉ host telemetry mới cho biết *tiến trình nào* sinh ra kết nối; khác biệt chỉ ở nguồn dữ liệu (Sysmon Event ID 1 ↔ `endpoint.events.process` của Elastic Defend). Muốn đúng bản Windows: cài Sysmon + agent trên một Windows VM có quyền admin.

**Lưu ý kỹ thuật:** trong `.fleet-policies`, input `endpoint` có mảng `streams` rỗng, nhưng **không** có nghĩa Defend tắt — Defend dùng policy revision riêng (`elastic-defend-endpoints` rev 1) và vẫn bắt sự kiện bình thường. Đừng kết luận từ trường `streams`.

**Artifact:** `evidence/s4-fleet-agent.json`, `s4-process-marker.json`, `s4-process-sample.json`, `s4-endpoint-datasets.json`, `s4-policy-inputs.json`.

## 7.5. Scenario 5 — File Transfer + PCAP ✅

**Thực hiện:**

```bash
# Host A (Kali 192.168.100.50)
printf 'SO-LAB-FILE-TRANSFER\n' > lab-test.txt
sha256sum lab-test.txt
python3 -m http.server 8000 --directory /tmp/s5

# Host B (Metasploitable 192.168.100.188)
wget http://192.168.100.50:8000/lab-test.txt
sha256sum lab-test.txt
```

**Hash khớp hai đầu:** `5ab59ed93f7282386eeb1df7e40ea22a4f14b82f44b5948dcf7675ceefc97e3c` (21 byte).

**Bằng chứng Zeek:**

- `zeek.http`: `GET /lab-test.txt`, status 200, UA `Wget/1.10.2`, 192.168.100.188:39281 → 192.168.100.50:8000, `resp_mime_types: text/plain`, `resp_fuids: FNAtJm20fj23bLNQI3`.
- `zeek.file`: `mime_type text/plain`, `seen_bytes 21`, **MD5 `ce8321b3b04a496aa87380397f792c7d`**, **SHA1 `23068caf35622b0d4b0d2fef11b3ebdb341dce1a`**, `source: HTTP`, fuid khớp `resp_fuids` của bản ghi HTTP.

**Lưu ý kỹ thuật:** Zeek tính **MD5/SHA1**, không tính SHA256; muốn đối chiếu SHA256 phải lấy từ host (như đã làm). Đây là lý do phải ghi cả hai loại hash.

**Artifact:** `evidence/s5-zeek-file.json`.

## 7.6. Scenario 6 — Honeypot (OpenCanary) ✅

**Triển khai:** OpenCanary (venv `/opt/canary`) trên Kali, `node_id = lab-canary-01`, giả lập **SSH trên 2222** (banner `SSH-2.0-OpenSSH_7.9p1`) và **HTTP trên 8081**, log JSON ra `/var/log/opencanary.log`.

**Kết nối thử từ Metasploitable:**

```bash
nc -v -z -w2 192.168.100.50 2222
wget http://192.168.100.50:8081/admin.php
```

**Bằng chứng:**

| Nguồn | Nội dung |
|---|---|
| Log canary (SSH) | `logtype 4000` (SSH connection): `src_host 192.168.100.188`, `src_port 43437`, `dst_port 2222`, `node_id lab-canary-01` |
| Log canary (HTTP) | `"192.168.100.188" - - "GET /admin.php HTTP/1.0" 404 "-" "Wget/1.10.2"` |
| Zeek | `zeek.http`: GET `/admin.php`, status 404, UA `Wget/1.10.2`, src 192.168.100.188, **dst port 8081** |

Honeypot giảm nhiễu đúng lý thuyết: không có lý do hợp lệ nào để một máy trong lab kết nối tới 2222/8081 của canary, nên một kết nối duy nhất đã đáng điều tra.

**Artifact:** `evidence/s6-zeek-http-canary.json` (+ log canary trích trong báo cáo này).

## 7.7. Cases

Chưa tạo Case bằng API trong phiên này. Đăng nhập SOC **đã hoạt động** (kiểm chứng end-to-end bằng đúng luồng Kratos: tạo flow → POST credentials → nhận session `aal1`), nhưng endpoint `/api/cases` của ứng dụng SOC trả 401/404 khi gọi bằng cookie phiên (cần token/CSRF riêng của app), nên Case vẫn để cho UI — khoảng 5 phút với tài khoản đã đặt lại.

Nội dung 6 Case, đã đủ bằng chứng để điền:

| Case | Title | Source → Target | Disposition | Đính kèm |
|---|---|---|---|---|
| 1 | LAB Scenario 1 — Network Service Scanning | 192.168.100.50 → 192.168.100.188 | Authorized lab activity | s1-scan.txt, s1-capture.pcap, s1-zeek-conn-scan.json |
| 2 | LAB Scenario 2 — SSH Brute Force | 192.168.100.50 → 192.168.100.188:22 | Authorized lab activity | s2-msf-authlog-failed.txt, s2-zeek-ssh.json |
| 3 | LAB Scenario 3 — Suspicious Web Activity | 192.168.100.50 → 192.168.100.188:80 | Authorized lab activity | s3-zeek-http-markers.json |
| 4 | LAB Scenario 4 — Suspicious Process on Endpoint | host `kali` (agent fafbd3a0) | Authorized lab activity | s4-process-marker.json |
| 5 | LAB Scenario 5 — File Transfer | 192.168.100.50:8000 → 192.168.100.188 | Authorized lab activity | s5-zeek-file.json, hash 2 đầu |
| 6 | LAB Scenario 6 — Honeypot Hit | 192.168.100.188 → 192.168.100.50:2222/8081 | Authorized lab activity | canary log, s6-zeek-http-canary.json |

## 7.8. Trạng thái lab bàn giao

- **IP tĩnh đã bền vững sau reboot** (đã test thật): Kali dùng unit `lab-net.service` (eth0 .60 / eth1 .50 + default route + DNS); Metasploitable dùng `/etc/network/interfaces` (eth0 .188). ssh/apache của target bật ở boot.
- **Mật khẩu** OS của SO, của VM lab, và mật khẩu SOC của `shy@gmail.com` đã được đặt lại trong các phiên này — **không ghi vào repo**, xem ghi chú bàn giao ngoài repo. Lệnh `so-user password` cũng **tắt MFA** của user đó.
- **Elastic Agent trên Kali** (từ Scenario 4) đã cài ở `/opt/Elastic/Agent`, service `elastic-agent` enabled, policy `endpoints-initial`. Ba thay đổi cần giữ để agent tiếp tục chạy: dòng `192.168.182.10 shyonion` trong `/etc/hosts` của Kali, CA của SO trong `/usr/local/share/ca-certificates/so-ca.crt`, và hai hostgroup `elastic_agent_endpoint` + `eval` (dải 192.168.182.0/24) trong firewall của SO.
- **Firewall SO đã mở thêm** cho dải lab: 8220/9200 (Fleet/ES) — ghi lại để biết đây là thay đổi có chủ đích, không phải mặc định của SO.
- Snapshot `before-passwd-reset` vẫn còn trên VM `secOnion`; xoá bằng `vmrun -T ws deleteSnapshot` khi đã chắc chắn.
- **Console VNC không mật khẩu vẫn bật** trên `kali` (5903) và `Metasploitable` (5902). Đã thử gỡ tự động nhưng **bị chặn bởi sandbox** (ổ D chỉ đọc với phiên hiện tại), nên để lại. Chỉ truy cập được từ chính máy host (Windows firewall chặn từ ngoài). Muốn gỡ: tắt VM → xoá 2 dòng `RemoteDisplay.vnc.*` trong file .vmx → bật lại.
- OpenCanary và HTTP server của Scenario 5 chạy dạng tiến trình tạm, đã dừng sau reboot; chạy lại theo §7.6 và §7.5 khi cần demo.
