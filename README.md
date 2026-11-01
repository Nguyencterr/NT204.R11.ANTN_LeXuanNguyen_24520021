# NT204.R11.ANTN – Packet Capture & Parser + IDS Core Engine (Assignment 1 + 2 + 3)

## 1. Tổng quan

Bài tập xây dựng chương trình thu thập và phân tích network packet phục vụ cho hệ thống IDS.

Chương trình hỗ trợ:

* Phân tích packet từ file PCAP.
* Capture packet trực tiếp.
* Phân tích IPv4, TCP và UDP.
* Nhận diện HTTP, DNS, SMTP và UNKNOWN.
* **Bài tập 2:** Decoder, Preprocessor và Flow/Connection Tracker cho IDS.
* **Bài tập 3 (mục 4.1):** Rule Loader của Core Engine — nạp rule từ file `.rules`.
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

### 2.3 Pipeline Bài tập 3 (mới đến mục 4.1)

```text
rules/*.rules
     │
┌────▼──────────────┐
│ 4.1 Rule Loader   │  ← đã triển khai (core_engine/rule_loader/)
└────┬──────────────┘
     │ RuleSourceEntry (raw_text + source_file + line_number + rule_ref)
┌────▼───────────────────┐
│ 4.2 Parser & Validator │  ← chưa triển khai
└────┬───────────────────┘
     │
┌────▼──────────────┐
│ 4.3 Repository /   │  ← chưa triển khai
│     Indexer        │
└────┬───────────────┘
     │
┌────▼──────────────┐     ┌─────────────────┐
│ 4.4 Matching      │◄────│ Normalized event │ (Bài tập 2)
└────┬──────────────┘     └─────────────────┘
     │
┌────▼──────────────┐
│ 4.5 Evaluation    │  ← chưa triển khai
└────┬──────────────┘
     │
┌────▼──────────────┐
│ 4.6 Detection     │  ← chưa triển khai
│     Event         │
└───────────────────┘
```

Rule Loader **không** phụ thuộc Scapy hay Flow Tracker; nó chỉ đọc rule và quản lý nguồn rule.

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
│   ├── assignment_2/         # Assignment 2 fixtures + results
│   └── BT3/                  # Assignment 3 fixtures, evidence, reports
│       ├── README.md
│       └── rule_loader/
│           ├── fixtures/     # .rules fixtures cho RL01–RL14
│           ├── evidence/     # log test + candidates.jsonl
│           └── REPORT_RULE_LOADER.md
├── rules/                    # rule mẫu + cấu hình Rule Loader
│   ├── rule_loader.json
│   ├── web.rules
│   ├── local.rules
│   └── dos.rules
├── core_engine/              # Assignment 3 Core Engine
│   └── rule_loader/          # mục 4.1: models.py, config.py, loader.py, __main__.py
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
│   ├── test_assignment2_*.py
│   └── test_rule_loader.py   # RL01–RL14 (Assignment 3, mục 4.1)
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

Chỉ test Rule Loader (Bài tập 3, mục 4.1):

```bash
python -m unittest tests.test_rule_loader -v
```

Tạo lại fixture Assignment 2:

```bash
python tests/generate_assignment2_fixtures.py
```

### 4.5 Chạy Rule Loader (Bài tập 3, mục 4.1)

```bash
# Dùng cấu hình của repository
python -m core_engine.rule_loader --config rules/rule_loader.json --stats --list

# Xuất candidate ra JSONL cho bước 4.2
python -m core_engine.rule_loader --config rules/rule_loader.json \
    --output output/candidates.jsonl

# Nạp nhanh nhiều file, không cần file cấu hình
python -m core_engine.rule_loader --rules rules/web.rules --rules rules/local.rules --list
```

| Option | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--config` | `rules/rule_loader.json` | File cấu hình JSON của Rule Loader |
| `--rules` | – | File `.rules` cần nạp (lặp lại được); thay thế `rule_files` trong config |
| `--base-dir` | thư mục file config | Base directory cho đường dẫn tương đối |
| `--output` | – | Ghi candidate ra JSONL |
| `--list` | – | In `rule_ref` + raw text từng candidate |
| `--stats` | – | In thống kê (mặc định in khi không có `--list`) |
| `--log-level` | `INFO` | Mức log diagnostic |

Exit code: `0` không lỗi, `1` có file/candidate lỗi, `2` cấu hình không dùng được.

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

### 8.3 Bài tập 3 — Rule Loader (RL01–RL14)

| ID | Tình huống | Kết quả |
| --: | --- | --- |
| RL01 | Rule + comment + dòng trắng | candidate đúng thứ tự, metadata nguồn đúng — **PASS** |
| RL02 | Nạp nhiều file `.rules` | giữ thứ tự file/rule, metadata không trộn — **PASS** |
| RL03 | File bị disable | không có candidate, `files_disabled=1` — **PASS** |
| RL04 | Disable một rule | rule trước/sau vẫn nạp, `rules_disabled=1` — **PASS** |
| RL05 | File không tồn tại / không phải file / không đọc được | warning + file khác vẫn nạp — **PASS** |
| RL06 | File sai extension | policy `strict` bỏ file, `lenient` nạp kèm warning — **PASS** |
| RL07 | Candidate processing error | warning theo `rule_ref`, candidate sau vẫn xử lý — **PASS** |
| RL08 | File rỗng / chỉ comment | 0 candidate, không exception — **PASS** |
| RL09 | Comment có whitespace phía trước | bị nhận diện là comment — **PASS** |
| RL10 | `#` bên trong nội dung rule | raw text giữ nguyên — **PASS** |
| RL11 | Relative path | `rule_ref` ổn định, không phụ thuộc `cwd` — **PASS** |
| RL12 | Selector không tồn tại | warning, rule khác vẫn nạp — **PASS** |
| RL13 | Lỗi cấu hình / encoding | báo rõ nguyên nhân, không tắt toàn bộ — **PASS** |
| RL14 | Regression / isolation | file lỗi + candidate lỗi không chặn phần còn lại — **PASS** |

Kết quả test gần nhất (chạy tại repo):

```text
Ran 37 tests in 0.006s
OK
```

Index testcase, bằng chứng và lệnh tái hiện: [`TEST/BT3/README.md`](TEST/BT3/README.md).
Report chi tiết: [`TEST/BT3/rule_loader/REPORT_RULE_LOADER.md`](TEST/BT3/rule_loader/REPORT_RULE_LOADER.md).

---

## 9. Bài tập 3 — Rule Loader (mục 4.1)

### 9.1 Mục tiêu

Rule Loader là module đầu vào của Core Engine: đọc một hoặc nhiều file `.rules`, bỏ comment và
dòng trắng, quản lý enable/disable theo cấu hình, cô lập lỗi, rồi bàn giao **rule candidate** cho
Rule Parser & Validator (mục 4.2). Loader **không** parse cú pháp Snort, không tìm SID/msg/content,
không so khớp với event.

### 9.2 Module

| Thành phần | Đường dẫn |
| --- | --- |
| Data contract | `core_engine/rule_loader/models.py` (`RuleSourceEntry`, `RuleLoadResult`, `RuleLoadWarning`, `RuleLoadStatistics`, `RuleFileSummary`) |
| Cấu hình | `core_engine/rule_loader/config.py` (`RuleLoaderConfig`, `RuleFileConfig`, `RuleLoaderConfigError`) |
| Loader | `core_engine/rule_loader/loader.py` (`RuleLoader.load()`) |
| CLI | `core_engine/rule_loader/__main__.py` (`python -m core_engine.rule_loader`) |
| Rule + config mẫu | `rules/web.rules`, `rules/local.rules`, `rules/dos.rules`, `rules/rule_loader.json` |

### 9.3 Cấu hình (`rules/rule_loader.json`)

Project không dùng YAML (không có dependency), nên cấu hình dùng JSON thuần standard library:

```json
{
  "rule_files": [
    {"path": "web.rules", "enabled": true},
    {"path": "local.rules", "enabled": true},
    {"path": "dos.rules", "enabled": false}
  ],
  "rule_overrides": {
    "local.rules:7": {"enabled": false}
  }
}
```

Quy tắc:

* `rule_files` giữ đúng thứ tự cấu hình; `enabled` bỏ trống ⇒ **bật** (mặc định rõ ràng).
* `rule_overrides` chọn rule theo `rule_ref = <source_file>:<line_number>`
  (ví dụ `local.rules:7`) vì mục 4.2 chưa parse SID.
* Giá trị override là `true`/`false` hoặc `{"enabled": bool}`.
* **Precedence:** disabled thắng enabled. File bị disable **không** được nạp lại bởi override
  `true` cho một rule bên trong (sẽ có warning `UNKNOWN_RULE_OVERRIDE`).
* Đường dẫn tương đối resolve theo `base_dir` — mặc định là thư mục chứa file cấu hình, nên
  `rule_ref` ổn định và không phụ thuộc current working directory.
* Entry cấu hình sai ⇒ warning `INVALID_CONFIG` và các entry khác vẫn nạp. Tài liệu JSON hỏng
  hoặc sai cấu trúc ⇒ `RuleLoaderConfigError` (không âm thầm tắt toàn bộ rule).

### 9.4 API

```python
from core_engine.rule_loader import RuleLoader, RuleLoaderConfig

config = RuleLoaderConfig.from_json_file("rules/rule_loader.json")
result = RuleLoader(config).load()

print(result.statistics.to_dict())      # files_loaded, rules_emitted, ...
for candidate in result.rules:          # giao cho mục 4.2
    parser_validator.parse(candidate)   # parser_validator chưa được viết ở mục 4.1

for warning in result.warnings:
    print(warning.code, warning.message)
```

Callback cũng được hỗ trợ: `RuleLoader(config).load(handler=parser_validator.parse)`.

`RuleSourceEntry`: `raw_text`, `source_file`, `path`, `line_number`, `rule_ref`, `file_index`,
`enabled`. `RuleLoadResult`: `rules`, `disabled_rules`, `warnings`, `statistics`, `file_results`.

### 9.5 Test

```bash
python -m unittest tests.test_rule_loader -v     # 37 test RL01–RL14
python -m unittest discover -s tests -v          # 91 test toàn repository
```

Fixture: `TEST/BT3/rule_loader/fixtures/`. Bằng chứng: `TEST/BT3/rule_loader/evidence/`.

### 9.6 Phạm vi đã hoàn thành

* **Đã làm — mục 4.1 Rule Loader:** đọc nhiều file, lọc comment/dòng trắng, enable/disable file
  và rule, cô lập lỗi, thống kê/logging, data contract bàn giao cho mục 4.2, test RL01–RL14.
* **Chưa làm:** 4.2 Rule Parser & Validator, 4.3 Rule Repository/Indexer, 4.4 Rule Matching
  Engine, 4.5 Rule Evaluation Engine, 4.6 Detection Event Generator; chưa có alert/logging/response.

---

## 10. Hạn chế hiện tại

* Không giải mã TLS/HTTPS (chỉ phân tích HTTP/1.x plaintext).
* MIME chỉ được decode khi payload chứa đủ header `Content-Transfer-Encoding` và body; không coi mọi body SMTP là MIME.
* DNS payload binary khi decode sang text sẽ bị đánh dấu `partial` — đây là hành vi đúng của character decoder.
* Raw payload chỉ giữ prefix có giới hạn (`max_payload_size`), dạng base64 để tương thích JSONL (đánh đổi riêng tư / volume dữ liệu).
* Flow tracker chưa xử lý IP fragmentation reassembly.
* Rule Loader (Bài tập 3, mục 4.1) chưa parse Snort rule: `rule_ref` dựa trên số dòng nên khi chèn/xoá dòng phải cập nhật `rule_overrides`; chưa có index/dedup rule (mục 4.3) và chưa xử lý directive `include`.
* Rule Loader không hot-reload file rule; mỗi lần đổi cấu hình phải gọi `load()` lại.
* Rule Loader chưa được nối vào `main.py` của pipeline Bài 1–2 (giữ nguyên hành vi CLI cũ); loader có CLI riêng `python -m core_engine.rule_loader`.
* Encoding mặc định UTF-8 `strict`; policy `replace` là tuỳ chọn có mất dữ liệu.

---

## 11. AI Disclosure

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

### Bài tập 3 (mục 4.1 Rule Loader)

Công cụ AI sử dụng: coding agent **DeepSeek V4.1 Flash Free** chạy trong **OpenCode**.

AI-assisted trong Assignment 3 — mục 4.1:

* Thiết kế data contract Rule Loader (`core_engine/rule_loader/models.py`).
* Viết cấu hình JSON và logic enable/disable file/rule (`core_engine/rule_loader/config.py`).
* Viết Rule Loader, cô lập lỗi, thống kê, logging (`core_engine/rule_loader/loader.py`).
* Viết CLI `python -m core_engine.rule_loader` (`core_engine/rule_loader/__main__.py`).
* Tạo rule mẫu và cấu hình (`rules/`), fixture `TEST/BT3/rule_loader/fixtures/`.
* Viết test RL01–RL14 (`tests/test_rule_loader.py`).
* Tạo report/evidence (`TEST/BT3/`) và cập nhật README.

Mục 4.2–4.6 **không** được AI sinh code trong lần làm này (chưa triển khai).
Toàn bộ lệnh test, log và kết quả trong `TEST/BT3/rule_loader/evidence/` là kết quả chạy thật
trong môi trường WSL; người thực hiện cần đọc, review và hiểu code trước khi nộp.
