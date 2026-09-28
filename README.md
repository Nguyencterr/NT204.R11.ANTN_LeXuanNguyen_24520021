# NT204.R11.ANTN – Packet Capture & Parser

## 1. Tổng quan

Bài tập xây dựng chương trình thu thập và phân tích network packet phục vụ cho hệ thống IDS.

Chương trình hỗ trợ:

* Phân tích packet từ file PCAP.
* Capture packet trực tiếp.
* Phân tích IPv4, TCP và UDP.
* Nhận diện HTTP, DNS, SMTP và UNKNOWN.
* Xuất kết quả dưới dạng JSONL.

Môi trường thực hiện:

* WSL / Ubuntu
* Python 3.14.4
* Scapy 2.7.0

---

## 2. Kiến trúc và Pipeline

```text
PCAP / Live Capture
        ↓
    Packet Capture
        ↓
     IPv4 Parser
        ↓
  TCP / UDP Parser
        ↓
Application Detection
        ↓
 HTTP / DNS / SMTP
        ↓
  Normalized Event
        ↓
       JSONL
```

PCAP và Live Capture sử dụng chung pipeline phân tích packet.

---

## 3. Cấu trúc thư mục

```text
.
├── README.md
├── TEST/
│   ├── tcp_handshake/
│   ├── tcp_data/
│   ├── udp/
│   ├── http_get/
│   ├── http_post/
│   ├── http_response/
│   ├── dns_query/
│   ├── dns_response/
│   ├── smtp_command/
│   ├── smtp_response/
│   ├── unknown/
│   └── malformed/
│
├── capture/
│   ├── __init__.py
│   ├── live.py
│   └── pcap.py
│
├── parser/
│   ├── __init__.py
│   ├── application.py
│   ├── network.py
│   ├── normalized.py
│   ├── transport.py
│   └── protocols/
│       ├── __init__.py
│       ├── http.py
│       ├── dns.py
│       └── smtp.py
│
├── tests/
│   ├── __init__.py
│   ├── generate_test_pcaps.py
│   └── generate_malformed_pcap.py
│
├── main.py
├── requirements.txt
└── output/
```

Các thư mục `__pycache__/` được Python tự động tạo trong quá trình chạy chương trình và không thuộc source code chính của project.

---

## 4. Test Cases

Project gồm 12 testcase:

| STT | Test case               |
| --: | ----------------------- |
|   1 | TCP Three-way Handshake |
|   2 | TCP Data                |
|   3 | UDP                     |
|   4 | HTTP GET                |
|   5 | HTTP POST               |
|   6 | HTTP Response           |
|   7 | DNS Query               |
|   8 | DNS Response            |
|   9 | SMTP Command            |
|  10 | SMTP Response           |
|  11 | Unknown Protocol        |
|  12 | Malformed Packet        |

Mỗi testcase gồm:

```text
input.pcap
result.jsonl
```

Các file được lưu tương ứng trong thư mục `TEST/`.

---

## 5. AI Disclosure

Công cụ AI sử dụng: ChatGPT (GPT-5.6 Luna)

AI được sử dụng để hỗ trợ trong quá trình thực hiện bài tập:

* Hỗ trợ viết và giải thích một phần code.
* Hỗ trợ tạo testcase và PCAP mẫu.
* Hỗ trợ debug và xử lý lỗi.

Code được kiểm tra và chạy lại trong môi trường WSL trước khi hoàn thiện.
