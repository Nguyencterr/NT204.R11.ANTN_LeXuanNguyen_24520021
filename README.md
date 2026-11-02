# NT204.R11.ANTN – Packet Capture & Parser + IDS Core Engine (Assignment 1 + 2 + 3)

## 1. Tổng quan

Bài tập xây dựng chương trình thu thập và phân tích network packet phục vụ cho hệ thống IDS.

Chương trình hỗ trợ:

* Phân tích packet từ file PCAP.
* Capture packet trực tiếp.
* Phân tích IPv4, TCP và UDP.
* Nhận diện HTTP, DNS, SMTP và UNKNOWN.
* **Bài tập 2:** Decoder, Preprocessor và Flow/Connection Tracker cho IDS.
* **Bài tập 3 (mục 4.1–4.6):** Core Engine — Rule Loader, Rule Parser & Validator,
  Rule Repository/Indexer, Rule Matching Engine, Rule Evaluation Engine và
  Detection Event Generator.
* Xuất kết quả dưới dạng JSONL (event + flow + detection).

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

### 2.3 Pipeline Bài tập 3 (mục 4.1–4.6)

```text
rules/*.rules
     │
┌────▼──────────────┐
│ 4.1 Rule Loader   │  core_engine/rule_loader/
└────┬──────────────┘
     │ RuleSourceEntry (raw_text + source_file + line_number + rule_ref)
┌────▼───────────────────┐
│ 4.2 Parser & Validator │  core_engine/rule_parser/
└────┬───────────────────┘
     │ valid / invalid / unsupported + InternalRule
┌────▼──────────────┐
│ 4.3 Repository /   │  core_engine/rule_repository/
│     Indexer        │
└────┬───────────────┘
     │
┌────▼──────────────┐     ┌──────────────────┐
│ 4.4 Matching      │◄────│ Normalized event │ (Bài tập 2)
└────┬──────────────┘     └──────────────────┘
     │  MATCH / NO_MATCH
┌────▼──────────────┐
│ 4.5 Evaluation    │  core_engine/evaluation/
└────┬──────────────┘
     │
┌────▼──────────────┐
│ 4.6 Detection     │  core_engine/detection/
│     Event         │
└───────────────────┘
     │
 Detection JSONL
```

Pipeline thật (`pipeline/pipeline.py`) chạy đúng thứ tự
`Decoder → Preprocessor → Flow Tracker → Rule Evaluation → Detection JSONL` cho cả PCAP
và live capture. Khi không truyền rule, pipeline giữ nguyên hành vi Bài tập 1–2.

Rule Loader **không** phụ thuộc Scapy hay Flow Tracker; nó chỉ đọc rule và quản lý nguồn rule.

---

## 3. Cấu trúc thư mục

```text
.
├── README.md
├── config.py                 # PipelineConfig: timeout, size limit, invalid policy
├── main.py                   # CLI (Bài 1 + 2 + 3)
├── TEST/
│   ├── tcp_handshake/ ...    # Assignment 1 artifacts
│   ├── ...
│   ├── assignment_2/         # Assignment 2 fixtures + results
│   └── BT3/                  # Assignment 3 fixtures, evidence, reports
│       ├── README.md
│       ├── rules/            # .rules fixtures cho TC01–TC14 + smoke
│       ├── rule_loader/      # report/evidence mục 4.1
│       ├── reports/          # report TC01–TC14 (mục 4.2–4.6)
│       └── evidence/
│           ├── test_logs/    # log unittest thật
│           ├── jsonl/        # parse result, candidate, event/flow/detection
│           └── other/        # log CLI
├── rules/                    # rule mẫu + cấu hình Rule Loader
│   ├── rule_loader.json
│   ├── web.rules
│   ├── local.rules
│   └── dos.rules
├── core_engine/              # Assignment 3 Core Engine
│   ├── rule_loader/          # 4.1: models.py, config.py, loader.py, __main__.py
│   ├── rule_parser/          # 4.2: models.py, tokenizer.py, parser.py
│   ├── rule_repository/      # 4.3: repository.py
│   ├── matching/             # 4.4: header, buffers, content, flow, conditions, engine
│   ├── evaluation/           # 4.5: engine.py
│   └── detection/            # 4.6: generator.py
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
│   ├── tracker.py            # FlowTracker / Flow
│   └── context.py            # adapter client/server + established cho flow:
├── pipeline/
│   └── pipeline.py           # IdsPipeline orchestrator
├── tests/
│   ├── generate_test_pcaps.py
│   ├── generate_malformed_pcap.py
│   ├── generate_assignment2_fixtures.py
│   ├── generate_bt3_evidence.py
│   ├── bt3_support.py
│   ├── test_assignment2_*.py
│   ├── test_assignment3_*.py # TC01–TC14 (mục 4.2–4.6)
│   └── test_rule_loader.py   # RL01–RL14 (mục 4.1)
├── requirements.txt
└── output/
```

---

## 4. Cách chạy

### 4.1 Chạy với PCAP

```bash
# Bài tập 2: event + flow
python main.py --pcap TEST/assignment_2/input_mixed.pcap \
    --output output/events.jsonl \
    --flows-output output/flows.jsonl

# Bài tập 3: thêm rule + detection
python main.py --pcap TEST/assignment_2/input_mixed.pcap \
    --rules TEST/BT3/rules/smoke.rules \
    --output output/events.jsonl \
    --flows-output output/flows.jsonl \
    --detections-output output/detections.jsonl
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
| `--rules` | – | File `.rules` hoặc thư mục (lặp lại được); thư mục được mở rộng theo `*.rules` đã sắp xếp |
| `--rule-config` | – | File JSON cấu hình Rule Loader (mục 4.1) |
| `--detections-output` | `output/detections.jsonl` | File Detection Event JSONL (chỉ ghi khi có rule) |
| `--duplicate-sid-policy` | `reject` | `reject` / `warn_keep`; không bao giờ ghi đè SID âm thầm |

### 4.4 Chạy test

```bash
python -m unittest discover -s tests -v
```

Chỉ test Rule Loader (Bài tập 3, mục 4.1):

```bash
python -m unittest tests.test_rule_loader -v
```

Chỉ test Core Engine mục 4.2–4.6 (TC01–TC14):

```bash
python -m unittest tests.test_assignment3_parser tests.test_assignment3_repository \
    tests.test_assignment3_matching tests.test_assignment3_evaluation \
    tests.test_assignment3_pipeline -v
```

Tạo lại toàn bộ JSONL/log bằng chứng Bài tập 3:

```bash
python tests/generate_bt3_evidence.py
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

### 8.4 Bài tập 3 — Core Engine (TC01–TC14)

| ID | Tình huống | Kết quả |
| --: | --- | --- |
| TC01 | Loader → Parser → Pipeline → Detection end-to-end | 3 detection đúng SID — **PASS** |
| TC02 | Rule sai cú pháp | `invalid`, rule sau vẫn parse — **PASS** |
| TC03 | Keyword ngoài phạm vi | `unsupported`, không vào repository — **PASS** |
| TC04 | Header any/IPv4/CIDR/port/range/hướng | parse + validate đúng — **PASS** |
| TC05 | `->` vs `<>` | một chiều / hai chiều kèm `orientation` — **PASS** |
| TC06 | Indexer candidate | không bỏ sót rule, thứ tự ổn định — **PASS** |
| TC07 | Header mismatch | short-circuit trước content — **PASS** |
| TC08 | `flow:` conditions | dùng tracker adapter, không bịa state — **PASS** |
| TC09 | `content` / `nocase` | phân biệt hoa/thường đúng — **PASS** |
| TC10 | `offset` / `depth` | cửa sổ tuyệt đối, biên đúng — **PASS** |
| TC11 | `distance` / `within` | tương đối + backtracking — **PASS** |
| TC12 | `flags` / `dsize` | đúng cờ, dsize theo payload — **PASS** |
| TC13 | Nhiều match | nhiều Detection Event độc lập — **PASS** |
| TC14 | Detection schema | đủ trường + `matched_info` — **PASS** |

Kết quả test gần nhất (chạy tại repo):

```text
Ran 63 tests in 0.031s
OK
```

Regression toàn repository: `Ran 154 tests ... OK` (91 test Bài 1–2 + 4.1, 63 test 4.2–4.6).

Report từng testcase: [`TEST/BT3/reports/README.md`](TEST/BT3/reports/README.md).
Bằng chứng thật: `TEST/BT3/evidence/` (test log, parse result JSONL, candidate JSONL,
event/flow/detection JSONL, CLI log).

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
    parser_validator.parse(candidate)   # RuleParserValidator (mục 4.2)

for warning in result.warnings:
    print(warning.code, warning.message)
```

Callback cũng được hỗ trợ: `RuleLoader(config).load(handler=parser_validator.parse)`.

`RuleSourceEntry`: `raw_text`, `source_file`, `path`, `line_number`, `rule_ref`, `file_index`,
`enabled`. `RuleLoadResult`: `rules`, `disabled_rules`, `warnings`, `statistics`, `file_results`.

### 9.5 Test

```bash
python -m unittest tests.test_rule_loader -v     # 37 test RL01–RL14
python -m unittest discover -s tests -v          # 154 test toàn repository
```

Fixture: `TEST/BT3/rule_loader/fixtures/`. Bằng chứng: `TEST/BT3/rule_loader/evidence/`.

### 9.6 Phạm vi

* **Đã làm — mục 4.1 Rule Loader:** đọc nhiều file, lọc comment/dòng trắng, enable/disable file
  và rule, cô lập lỗi, thống kê/logging, data contract bàn giao cho mục 4.2, test RL01–RL14.
* **Đã làm — mục 4.2–4.6:** parser/validator, repository/indexer, matching, evaluation và
  detection generator; xem mục 10 bên dưới.

---

## 10. Bài tập 3 — Core Engine (mục 4.2–4.6)

### 10.1 Subset Snort được hỗ trợ

Đây là **subset**, không phải Snort đầy đủ. Mọi thứ ngoài bảng dưới được phân loại
`unsupported` (hợp lệ nhưng ngoài phạm vi) hoặc `invalid` (sai cú pháp), không bị bỏ qua
âm thầm.

| Thành phần | Giá trị hỗ trợ |
| --- | --- |
| Action | `alert` |
| Protocol | `tcp`, `udp` |
| Address | `any`, IPv4 đơn, IPv4 CIDR (`192.168.1.0/24`) |
| Port | `any`, port đơn, range `1000:2000`, range mở `:1024`, `1024:` |
| Direction | `->` (một chiều), `<>` (hai chiều) |
| Metadata | `msg` (bắt buộc), `sid` (bắt buộc), `rev` (mặc định `1`), `classtype`, `priority` |
| Content | `content`, `nocase`, `offset`, `depth`, `distance`, `within` |
| TCP | `flags` với `S`, `A`, `F`, `R`, `P`, `U` |
| Payload | `dsize` với `>`, `<`, `=`, `>=`, `<=`; số trần nghĩa là `=` |
| Flow | `flow:to_server`, `to_client`, `established`, `not_established` |

Ngoài phạm vi (ví dụ): action khác `alert`, `icmp`, IPv6, phủ định `!`, danh sách địa chỉ/port,
`pcre`, `byte_test`, `byte_jump`, `uricontent`, `http_*`, `rawbytes`, hex content `|...|`,
escape `\xNN`, `flags` modifier `+*!`, `dsize` dạng range/`!=`, `flow:only_stream`.
Các keyword no-value đã biết của Snort được báo `unsupported`; token lạ không có
`name:value` được báo `invalid`.

### 10.2 Parser & Validator (`core_engine/rule_parser/`)

* Mỗi candidate nhận đúng một trong ba trạng thái: `valid`, `invalid`, `unsupported`.
* `sid` và `msg` là bắt buộc; `rev` thiếu ⇒ `1` (được tài liệu hoá).
* Option trùng lặp, modifier không có `content` trước, `distance`/`within` trộn với
  `offset`/`depth`, `flags` trên UDP, `dsize` sai kiểu ⇒ `invalid`.
* Rule lỗi được cô lập: parser luôn trả kết quả, không ném exception ra pipeline.
* Kết quả là `InternalRule` có kiểu rõ ràng, không phải `dict` tự do.

### 10.3 Repository / Indexer (`core_engine/rule_repository/`)

* Chỉ rule `valid` được đưa vào tập so khớp; `invalid`/`unsupported` được giữ làm
  diagnostic để truy vết.
* **Duplicate SID:** mặc định `reject` (rule sau bị từ chối, rule đầu giữ nguyên).
  Policy `warn_keep` giữ cả hai và ghi diagnostic; **không bao giờ ghi đè âm thầm**.
* Index theo protocol + port trả **superset** candidate, sau đó lọc lại bằng
  `match_rule_header` dùng chung với matching engine — index không thể bỏ sót rule mà
  matcher sẽ khớp.
* `CandidateSelection` báo `pool_size`, `port_candidate_count`, `candidate_count`, `sids`.

### 10.4 Matching Engine (`core_engine/matching/`)

Thứ tự đánh giá (short-circuit):

1. Header: protocol, địa chỉ, port, hướng.
2. `flow:` conditions.
3. TCP `flags`.
4. `dsize`.
5. Chuỗi `content`.

Quy ước quan trọng:

* `->` chỉ khớp chiều thuận. `<>` khớp cả hai chiều và ghi `orientation`
  (`forward`/`reverse`) vào `matched_info`.
* Buffer tìm kiếm tách biệt, không nối: `payload`, `decoded_payload`, `http_uri`,
  `http_body`, `http_decoded_body`, `mime_body`, `dns_name`, `http_host`.
* `offset`/`depth` là cửa sổ tuyệt đối `[offset, offset + depth)`.
* `distance`/`within` neo vào cuối match trước: `[prev_end + distance, prev_end + distance + within)`.
* Nếu lần xuất hiện đầu không dẫn tới chuỗi khớp, matcher **backtrack** sang lần sau.
* `nocase` chỉ gập ASCII (`bytes.lower()`) để giữ đúng vị trí byte UTF-8.
* `flags`: mọi cờ khai báo phải có mặt; cờ thừa không cản trở; thiếu flags ⇒ NO_MATCH.
* `dsize`: dùng `payload_length` (không dùng `packet_length`/frame/flow byte).

### 10.5 Flow adapter (`flow/context.py`)

Tracker Bài 2 không tự biết client/server, nên adapter suy luận có bằng chứng:

1. TCP SYN (không ACK) ⇒ sender là client.
2. Nếu đúng một endpoint dùng port server nổi tiếng ⇒ endpoint đó là server.
3. Nếu cả hai port đã biết và khác nhau ⇒ port thấp hơn là server (heuristic).
4. Còn lại ⇒ vai trò `unknown`; `to_server`/`to_client` là `null`, rule yêu cầu sẽ
   NO_MATCH thay vì bịa state.

`role_source` ghi lại quy tắc đã dùng. TCP `established` dựa trên `ever_established`.
UDP không mô phỏng handshake: flow `OPEN` được quy ước là `established` (tài liệu hoá rõ).

### 10.6 Evaluation & Detection (`core_engine/evaluation/`, `core_engine/detection/`)

* Mỗi event: lấy candidate → đánh giá **tất cả** candidate → thu **tất cả** match.
* Lỗi một candidate/detection được cô lập, không dừng event hay pipeline.
* Thống kê: `events_evaluated`, `candidate_rules`, `matches`, `no_match_count`,
  `invalid_event_count`, `errors`, `detections_generated`.
* Mỗi match sinh một Detection Event riêng, schema `bt3.detection.v1`.

Detection JSONL mẫu:

```json
{
  "schema_version": "bt3.detection.v1",
  "timestamp": 1001.0,
  "packet_id": 6,
  "action": "alert",
  "sid": 4101001,
  "rev": 1,
  "msg": "BT3 smoke SQLi decoded URI",
  "priority": 1,
  "classtype": "web-application-attack",
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "src_port": 50001,
  "dst_port": 8080,
  "protocol": "TCP",
  "application_protocol": "HTTP",
  "flow_id": "sha256[:32]",
  "matched_info": {
    "orientation": "forward",
    "buffer": "http_uri",
    "content_matches": [
      {"condition_index": 0, "content": "OR 1=1", "position": 12, "end": 18}
    ],
    "details": {"header": {}, "flow": {}, "flags": {}, "dsize": {}, "content": {}},
    "reason": null,
    "flow_conditions": null
  },
  "rule": {
    "sid": 4101001, "rev": 1, "msg": "BT3 smoke SQLi decoded URI",
    "rule_ref": "smoke.rules:2", "source_file": "smoke.rules",
    "line_number": 2, "raw_text": "alert tcp ..."
  }
}
```

### 10.7 Tích hợp pipeline và CLI

* `pipeline/pipeline.py`: `Decoder → Preprocessor → Tracker → Rule Evaluation`, dùng chung
  cho PCAP và live capture.
* `main.py` nạp rule qua `--rules` hoặc `--rule-config`, parse, build repository, rồi ghi
  Detection JSONL qua `--detections-output`.
* File output được reset trước khi ghi; writer luôn được đóng trong `finally`.
* Không truyền rule ⇒ không tạo detection writer, hành vi Bài 1–2 giữ nguyên.
* Rule lỗi chỉ in cảnh báo ra `stderr`; process vẫn tiếp tục.

### 10.8 Test và bằng chứng

```bash
python -m unittest tests.test_assignment3_parser tests.test_assignment3_repository \
    tests.test_assignment3_matching tests.test_assignment3_evaluation \
    tests.test_assignment3_pipeline -v
python -m unittest discover -s tests -v
```

Kết quả thật: **63/63** test Assignment 3 PASS, **154/154** test toàn repository PASS.
Report TC01–TC14: `TEST/BT3/reports/`. Bằng chứng: `TEST/BT3/evidence/`.

### 10.9 Hạn chế của mục 4.2–4.6

* Chỉ hỗ trợ subset ở mục 10.1; không có PCRE, binary content, sticky buffer `http_*`,
  danh sách/phủ định địa chỉ-port.
* Matching chạy trên **từng packet event**, chưa reassembly TCP stream; một pattern nằm
  vắt qua hai packet sẽ không khớp.
* Chưa có alert suppression/thresholding: cùng một flow có thể sinh nhiều detection nếu
  nhiều packet khớp.
* Vai trò client/server là heuristic có bằng chứng, không phải ground truth.
* UDP `established` là quy ước của bài, không phải trạng thái giao thức thật.
* Chưa xử lý IP fragmentation và chưa hot-reload rule khi đang chạy.
* Detection chưa được gửi tới SIEM/response; chỉ ghi JSONL.

---

## 11. Hạn chế hiện tại

* Không giải mã TLS/HTTPS (chỉ phân tích HTTP/1.x plaintext).
* MIME chỉ được decode khi payload chứa đủ header `Content-Transfer-Encoding` và body; không coi mọi body SMTP là MIME.
* DNS payload binary khi decode sang text sẽ bị đánh dấu `partial` — đây là hành vi đúng của character decoder.
* Raw payload chỉ giữ prefix có giới hạn (`max_payload_size`), dạng base64 để tương thích JSONL (đánh đổi riêng tư / volume dữ liệu).
* Flow tracker chưa xử lý IP fragmentation reassembly.
* Rule `rule_ref` dựa trên số dòng nên khi chèn/xoá dòng phải cập nhật `rule_overrides`; chưa xử lý directive `include`.
* Rule Loader không hot-reload file rule; mỗi lần đổi cấu hình phải gọi `load()` lại.
* Rule Loader có CLI riêng `python -m core_engine.rule_loader`; pipeline dùng chung loader qua `--rules`/`--rule-config`.
* Encoding mặc định UTF-8 `strict`; policy `replace` là tuỳ chọn có mất dữ liệu.

---

## 12. AI Disclosure

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

### Bài tập 3 (mục 4.2–4.6 Rule Parser → Detection)

Công cụ AI sử dụng: coding agent **DeepSeek V4.1 Flash Free** chạy trong **OpenCode**,
tiếp tục trên cùng repository.

AI-assisted trong Assignment 3 — mục 4.2–4.6:

* Thiết kế/viết tokenizer, parser, validator và `InternalRule`
  (`core_engine/rule_parser/`).
* Viết repository/indexer, duplicate-SID policy, diagnostic và thống kê candidate
  (`core_engine/rule_repository/`).
* Viết matching engine: header, buffer, content/modifier, flags, dsize, flow
  (`core_engine/matching/`).
* Viết evaluation engine, thống kê và cô lập lỗi (`core_engine/evaluation/`).
* Viết Detection Event Generator và schema `bt3.detection.v1`
  (`core_engine/detection/`).
* Viết adapter client/server + `established` cho `flow:` (`flow/context.py`) và bổ sung
  additive `syn_sender`, `ever_established`, `last_context` vào `flow/tracker.py`.
* Tích hợp rule engine vào `pipeline/pipeline.py` và CLI `main.py`.
* Tạo fixture `.rules`, test TC01–TC14 (`tests/test_assignment3_*.py`), helper
  `tests/bt3_support.py` và script tái tạo bằng chứng `tests/generate_bt3_evidence.py`.
* Tạo report `TEST/BT3/reports/`, JSONL/log bằng chứng `TEST/BT3/evidence/` và cập nhật
  README.

**Minh bạch về kết quả:** mọi log test, JSONL output và CLI log trong
`TEST/BT3/evidence/` đều được sinh bằng lệnh chạy thật trong môi trường WSL của repository;
không có log hay kết quả nào được viết tay thay thế. Các con số được báo cáo:
63/63 test Assignment 3 PASS và 154/154 test toàn repository PASS tại thời điểm tạo report.
Người thực hiện cần đọc, review và hiểu code trước khi nộp.
