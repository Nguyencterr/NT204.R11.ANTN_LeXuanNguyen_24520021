# NT204.R11.ANTN – Packet Capture & Parser (Assignment 1 + Assignment 2)

## 1. Tổng quan

Bài tập xây dựng chương trình thu thập và phân tích network packet phục vụ cho hệ thống IDS.

Chương trình hỗ trợ:

* Phân tích packet từ file PCAP.
* Capture packet trực tiếp.
* Phân tích IPv4, TCP và UDP.
* Nhận diện HTTP, DNS, SMTP và UNKNOWN.
* **Bài tập 2:** Decoder, Preprocessor và Flow/Connection Tracker cho IDS.
* Xuất kết quả dưới dạng JSONL (event + flow).

Môi trường thực hiện:

* WSL / Ubuntu
* Python 3.14.4
* Scapy 2.7.0

---

## 2. Kiến trúc và Pipeline

### 2.1 Pipeline Bài tập 1

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

### 2.2 Pipeline Bài tập 2

```text
PCAP / Live Capture
        ↓
Packet Capture & Parser (Bài tập 1)
        ↓
        Decoder          (URL/form, HTML entities, MIME Base64/Quoted-Printable, charset)
        ↓
     Preprocessor        (validation + normalization, status valid/partial/invalid)
        ↓
Flow/Connection Tracker  (bidirectional 5-tuple flows, TCP/UDP state, idle timeout)
        ↓
 Normalized event (JSONL)  +  finalized flow records (JSONL)
        ↓
Future Feature Extractor / Detection Engine
```

PCAP và Live Capture sử dụng chung một pipeline (`pipeline/pipeline.py`) với đúng thứ tự `decoder → preprocessor → tracker`.

---

## 3. Cấu trúc thư mục

```text
.
├── README.md
├── config.py                 # PipelineConfig: timeout, size limit, invalid policy
├── main.py                   # CLI (Assignment 1 options + Assignment 2 options)
├── TEST/
│   ├── tcp_handshake/ ...    # Assignment 1 artifacts
│   ├── ...
│   └── assignment_2/         # Assignment 2 fixtures + results
├── capture/
│   ├── __init__.py
│   ├── live.py
│   └── pcap.py
├── parser/
│   ├── __init__.py           # parse_packet() (+ raw payload b64, packet length)
│   ├── application.py
│   ├── network.py
│   ├── normalized.py         # NormalizedEvent
│   ├── transport.py
│   └── protocols/
├── common/
│   ├── events.py             # as_event_dict()
│   └── jsonl.py              # JsonlWriter / read_jsonl
├── decoder/
│   └── decoder.py            # decode_event()
├── preprocessor/
│   └── preprocessor.py       # preprocess_event()
├── flow/
│   └── tracker.py            # FlowTracker / Flow
├── pipeline/
│   └── pipeline.py           # IdsPipeline orchestrator
├── tests/
│   ├── generate_test_pcaps.py
│   ├── generate_malformed_pcap.py
│   ├── generate_assignment2_fixtures.py
│   └── test_assignment2_*.py
├── requirements.txt
└── output/
```

---

## 4. Cách chạy

### 4.1 Chạy với PCAP

```bash
python main.py --pcap TEST/assignment_2/input_mixed.pcap \
    --output output/events.jsonl \
    --flows-output output/flows.jsonl
```

### 4.2 Chạy live capture

```bash
python main.py --interface eth0 --count 100
python main.py --list-interfaces
```

### 4.3 Options CLI

| Option | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--pcap` | – | File PCAP đầu vào |
| `--interface` | – | Interface live capture |
| `--output` | `output/events.jsonl` | File event JSONL |
| `--flows-output` | `output/flows.jsonl` | File flow JSONL (Assignment 2) |
| `--count` | `0` | Số packet live capture (0 = không giới hạn) |
| `--list-interfaces` | – | Liệt kê interface |
| `--tcp-idle-timeout` | `120.0` s | Idle timeout TCP |
| `--udp-idle-timeout` | `30.0` s | Idle timeout UDP |
| `--max-decoded-size` | `65536` | Giới hạn độ dài chuỗi đã decode (char) |
| `--max-payload-size` | `8192` | Giới hạn raw payload xử lý trong Decoder (bytes) |
| `--invalid-event-policy` | `mark` | `keep` / `mark` / `skip` cho event invalid |

### 4.4 Chạy test

```bash
python -m unittest discover -s tests -v
```

Tạo lại fixture Assignment 2:

```bash
python tests/generate_assignment2_fixtures.py
```

---

## 5. Cấu hình (config.py)

`PipelineConfig` cung cấp default:

* `tcp_idle_timeout = 120.0`, `udp_idle_timeout = 30.0`
* `max_decoded_size = 65536`, `max_payload_size = 8192`
* `invalid_event_policy = "mark"` (`keep` giữ nguyên event invalid; `mark` giữ và gắn cờ; `skip` bỏ event invalid)

---

## 6. Nhiệm vụ từng module Assignment 2

### Decoder (`decoder/decoder.py`)

* Giữ nguyên giá trị raw (ví dụ `raw_uri`/`raw_path`/`raw_body`), thêm giá trị đã decode cạnh bên.
* Percent/URL decoding cho HTTP URI/path; form decoding (`+` = space, `parse_qsl`) chỉ khi `application/x-www-form-urlencoded`.
* HTML entity decoding (`html.unescape`) cho body HTML.
* MIME Base64 và Quoted-Printable chỉ khi có header `Content-Transfer-Encoding` tương ứng.
* Character decoding UTF-8; byte invalid → `decode_status = "partial"`, không crash.
* Giới hạn `max_decoded_size`/`max_payload_size`; lỗi một field không dừng pipeline.

Thêm metadata: `decoded.{http,html,mime,text}`, `decode_status`, `decode_reason`.

### Preprocessor (`preprocessor/preprocessor.py`)

* Validate: `packet_id`, `timestamp`, IP, transport protocol, port 0–65535, application protocol.
* Normalize: tên protocol (TCP/UDP/HTTP/DNS/SMTP), IP (ipaddress canonical), HTTP header name (lowercase), Host (lowercase), URI, timestamp (float).
* Field optional thiếu → `null` / `[]` theo schema, không exception.
* Output: `preprocess_status` (`valid`/`partial`/`invalid`), `processing_action` (`keep`/`mark`/`skip`), `preprocess_reason`, `preprocess_warnings`, `normalized`.

### Flow/Connection Tracker (`flow/tracker.py`)

* Key bidirectional 5-tuple `(src_ip, dst_ip, src_port, dst_port, transport_protocol)`; endpoint đảo vẫn cùng flow, direction được giữ riêng.
* `flow_id` = SHA-256 digest của canonical key + generation (ổn định, không dùng `hash()` Python).
* TCP state: `NEW`/`HANDSHAKE` → `ESTABLISHED` → `CLOSING` → `CLOSED`; `RST` → `RESET` (terminal). Quy tắc: SYN mở flow; SYN+ACK ghi nhận chiều trả lời; ACK cuối → ESTABLISHED; FIN hai chiều → CLOSED; RST → RESET.
* UDP: không phát minh handshake TCP; state `OPEN`, flow hai chiều trong idle window.
* Idle timeout riêng cho TCP/UDP; packet đến sau idle → finalize flow cũ, xóa khỏi active table, tạo flow mới.
* `flush()` cuối PCAP/cuối live capture finalize các flow còn lại (reason `flush`/`timeout`/`closed`/`reset`).
* Byte counter dùng full packet length (`packet_length`) khi có; fallback `payload_length` ghi rõ `byte_count_basis` (`packet`/`payload`/`mixed`).
* `application_protocol` được cập nhật khi có packet HTTP/DNS/SMTP; `UNKNOWN` không ghi đè giá trị đã biết.

---

## 7. Schema JSONL

### 7.1 Event JSONL (mỗi dòng một object)

```json
{
  "packet_id": 1,
  "timestamp": 1790530617.4,
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "network": {"protocol": "IPv4"},
  "transport": {"protocol": "TCP", "src_port": 50000, "dst_port": 80, "flags": "S"},
  "application": {"protocol": "HTTP", "...": "..."},
  "payload_length": 0,
  "packet_length": 54,
  "raw_payload_b64": "base64...",   // có giới hạn, null nếu không có payload
  "raw_payload_truncated": false,
  "status": "OK",
  "errors": [],
  "decoded": {"http": {...}, "html": null, "mime": null, "text": {...}},
  "decode_status": "ok",
  "decode_reason": null,
  "normalized": {"src_ip": "...", "transport_protocol": "TCP", "http_headers": {...}},
  "src_port": 50000,
  "dst_port": 80,
  "transport_protocol": "TCP",
  "application_protocol": "HTTP",
  "preprocess_status": "valid",
  "processing_action": "keep",
  "preprocess_reason": null,
  "preprocess_warnings": []
}
```

### 7.2 Flow JSONL

```json
{
  "flow_id": "sha256[:32]",
  "protocol": "TCP",
  "application_protocol": "HTTP",
  "state": "ESTABLISHED",
  "endpoint_a": {"ip": "192.168.1.10", "port": 50000},
  "endpoint_b": {"ip": "192.168.1.20", "port": 80},
  "start_time": 1000.0,
  "last_seen": 1000.2,
  "duration": 0.2,
  "packet_count": 3,
  "byte_count": 162,
  "byte_count_basis": "packet",
  "forward_packet_count": 2,
  "backward_packet_count": 1,
  "forward_byte_count": 108,
  "backward_byte_count": 54,
  "SYN_count": 2,
  "ACK_count": 2,
  "FIN_count": 0,
  "RST_count": 0,
  "finalization_reason": "flush"
}
```

**Byte counter:** mặc định dùng full packet length (`packet_length`) cho cả overall lẫn từng direction; nếu không có `packet_length` thì fallback `payload_length` và đánh dấu `byte_count_basis`. Không trộn hai định nghĩa trong cùng counter (nếu xảy ra → `byte_count_basis = "mixed"`).

---

## 8. Test Cases

### 8.1 Bài tập 1 (12 testcase)

| STT | Test case |
| --: | --------- |
| 1–12 | TCP handshake, TCP data, UDP, HTTP GET/POST/Response, DNS query/response, SMTP command/response, Unknown, Malformed |

Mỗi testcase gồm `input.pcap` + `result.jsonl` trong `TEST/`.

### 8.2 Bài tập 2 (T01–T14)

| ID | Tình huống | Kết quả chính |
| --: | --- | --- |
| T01 | HTTP URI percent-encoding | URI decoded đúng, raw giữ nguyên — **PASS** |
| T02 | HTML entity | text decoded đúng, không crash — **PASS** |
| T03 | SMTP/MIME Base64 + Quoted-Printable | body decoded đúng + decode status — **PASS** |
| T04 | Invalid bytes / UTF-8 không hợp lệ | đánh dấu partial; pipeline tiếp tục — **PASS** |
| T05 | Normalization | protocol/header/IP/domain/URI nhất quán — **PASS** |
| T06 | Missing field | null/[] nhất quán, không exception — **PASS** |
| T07 | TCP handshake SYN → SYN/ACK → ACK | một flow, state `ESTABLISHED` — **PASS** |
| T08 | Bidirectional flow | hai chiều cùng `flow_id`, direction/count đúng — **PASS** |
| T09 | TCP FIN/ACK hoặc RST | `CLOSED`/`RESET` phù hợp — **PASS** |
| T10 | UDP query/response | một UDP flow hai chiều, counter đúng — **PASS** |
| T11 | Concurrent flows | endpoint khác nhau là flow riêng — **PASS** |
| T12 | Idle timeout | flow finalize + xóa khỏi active table — **PASS** |
| T13 | Statistics | packet/byte/flag counters và duration đúng — **PASS** |
| T14 | Malformed/unsupported event | không crash; status/reason phù hợp — **PASS** |

Kết quả test gần nhất (chạy tại repo):

```text
Ran 54 tests in 0.012s
OK
```

Phân bổ: decoder 16, preprocessor 14, tracker 15, pipeline 9.

Báo cáo chi tiết từng testcase (mục tiêu, input, tiêu chí PASS, kết quả thực tế,
bằng chứng và hạn chế) nằm tại
[`TEST/assignment_2/reports/`](TEST/assignment_2/reports/README.md), kèm bằng
chứng thô trong `TEST/assignment_2/evidence/`.

Fixture tái hiện: `TEST/assignment_2/input_mixed.pcap`, `result_events.jsonl`, `result_flows.jsonl` (tạo bằng `tests/generate_assignment2_fixtures.py`).

---

## 9. Hạn chế hiện tại

* Không giải mã TLS/HTTPS (chỉ phân tích HTTP/1.x plaintext).
* MIME chỉ được decode khi payload chứa đủ header `Content-Transfer-Encoding` và body; không coi mọi body SMTP là MIME.
* DNS payload binary khi decode sang text sẽ bị đánh dấu `partial` — đây là hành vi đúng của character decoder.
* Raw payload chỉ giữ prefix có giới hạn (`max_payload_size`), dạng base64 để tương thích JSONL (đánh đổi riêng tư / volume dữ liệu).
* Flow tracker chưa xử lý IP fragmentation reassembly.

---

## 10. AI Disclosure

### Bài tập 1

Công cụ AI sử dụng: ChatGPT (GPT-5.6 Luna)

AI được sử dụng để hỗ trợ trong quá trình thực hiện bài tập:

* Hỗ trợ viết và giải thích một phần code.
* Hỗ trợ tạo testcase và PCAP mẫu.
* Hỗ trợ debug và xử lý lỗi.

### Bài tập 2

Công cụ AI sử dụng: coding agent Big Pickle (opencode) chạy trên repository.

AI-assisted trong Assignment 2:

* Thiết kế event contract và tích hợp pipeline `decoder → preprocessor → tracker` (`parser/`, `pipeline/`, `main.py`).
* Viết module Decoder (URL/form/HTML/MIME/charset) trong `decoder/`.
* Viết module Preprocessor (validation/normalization/policy) trong `preprocessor/`.
* Viết module Flow/Connection Tracker (state máy TCP/UDP, timeout, `flow_id` SHA-256) trong `flow/`.
* Viết `config.py`, helper JSONL (`common/`), test T01–T14 (`tests/test_assignment2_*.py`) và fixture `TEST/assignment_2/`.
* Cập nhật README này.

Tất cả code và kết quả test đều được chạy lại thực tế trong môi trường WSL trước khi hoàn thiện; không bịa kết quả.