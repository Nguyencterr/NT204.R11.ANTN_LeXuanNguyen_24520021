# REPORT — Bài tập 3, mục 4.1: Rule Loader

* **Repository:** `NT204.R11.ANTN_LeXuanNguyen_24520021`
* **Phạm vi:** Bài tập 3 — Core Engine, **chỉ mục 4.1 Rule Loader**
* **Ngày chạy test gần nhất:** 2026-11-01 (log trong `evidence/`)
* **Kết quả tổng hợp:** 37/37 test Rule Loader **PASS**; 91/91 test toàn repository **PASS**

> Mục 4.2 (Rule Parser & Validator), 4.3 (Rule Repository/Indexer), 4.4 (Matching),
> 4.5 (Evaluation), 4.6 (Detection Event Generator) **chưa triển khai** trong báo cáo này.

---

## 1. Mục tiêu Rule Loader

Rule Loader là module đầu vào của Core Engine. Nhiệm vụ:

1. Đọc một hoặc nhiều file `.rules` theo thứ tự cấu hình.
2. Bỏ qua dòng trống và dòng comment (`#` ở vị trí ký tự không phải whitespace đầu tiên).
3. Giữ nguyên văn nội dung rule, không parse cú pháp Snort, không tự suy ra SID/msg/protocol/content.
4. Gắn metadata nguồn (`source_file`, `line_number`, `rule_ref`) để truy vết.
5. Cho phép bật/tắt **từng file** và **từng rule** bằng cấu hình (không sửa source code).
6. Cô lập lỗi: một file lỗi, một entry cấu hình lỗi hoặc một candidate lỗi không làm dừng các file/rule khác.
7. Bàn giao danh sách candidate cho Rule Parser & Validator (mục 4.2) qua data contract rõ ràng.

Rule Loader **không** phụ thuộc Scapy, không phụ thuộc Flow Tracker, không đánh giá rule với event.

---

## 2. Kiến trúc và luồng xử lý

### 2.1 Vị trí trong Core Engine

```text
Bài 1–2:  PCAP / Live → Parser → Decoder → Preprocessor → Flow Tracker → event JSONL + flow JSONL
                                                                              │
Bài 3:                                                    Core Engine          ▼
                                              ┌──────────────────────────────────────┐
                                              │ 4.1 Rule Loader   (đã làm)           │
                                              │   .rules files → RuleSourceEntry     │
                                              └──────────────┬───────────────────────┘
                                                             │ result.rules
                                              ┌──────────────▼───────────────────────┐
                                              │ 4.2 Rule Parser & Validator (chưa)   │
                                              └──────────────┬───────────────────────┘
                                                             │
                                          4.3 Repository/Indexer → 4.4 Matching
                                          → 4.5 Evaluation → 4.6 Detection Event
```

### 2.2 Luồng xử lý của Loader

```text
RuleLoaderConfig (JSON / dataclass)
        │
        ├─ 1. problems của config          → warning INVALID_CONFIG (không dừng)
        ├─ 2. chuẩn hoá base_dir, path     → (display_path, absolute_path)
        │
        └─ với từng file, theo thứ tự cấu hình:
               ├─ enabled == false         → bỏ qua, thống kê files_disabled, warning FILE_DISABLED (info)
               ├─ sai extension            → policy strict: bỏ qua + EXTENSION_NOT_ALLOWED
               │                             policy lenient: nạp + EXTENSION_NOT_ALLOWED
               ├─ mở file lỗi              → FILE_NOT_FOUND / FILE_NOT_REGULAR / FILE_UNREADABLE / FILE_IO_ERROR
               ├─ decode lỗi               → FILE_ENCODING_ERROR (hủy toàn bộ candidate của file đó)
               ├─ đọc từng dòng:
               │     ├─ dòng trắng         → lines_skipped_blank
               │     ├─ comment (kể cả có whitespace trước #) → lines_skipped_comment
               │     └─ còn lại            → RuleSourceEntry (raw_text giữ nguyên)
               ├─ rule_overrides[rule_ref] == false → loại khỏi output, thống kê rules_disabled, warning RULE_DISABLED
               └─ không có candidate       → FILE_EMPTY / FILE_NO_RULES (info, không phải lỗi)
        │
        ├─ override không khớp rule nào → UNKNOWN_RULE_OVERRIDE
        ├─ handler (tuỳ chọn) lỗi       → CANDIDATE_HANDLER_ERROR, chỉ candidate đó bị tính failed
        └─ RuleLoadResult { rules, disabled_rules, warnings, statistics, file_results }
```

Module:

| File | Vai trò |
| --- | --- |
| `core_engine/rule_loader/models.py` | Data contract: `RuleSourceEntry`, `RuleLoadWarning`, `RuleFileSummary`, `RuleLoadStatistics`, `RuleLoadResult`, mã warning |
| `core_engine/rule_loader/config.py` | `RuleLoaderConfig`, `RuleFileConfig`, `RuleLoaderConfigError`, đọc/kiểm tra JSON, chuẩn hoá `rule_ref` |
| `core_engine/rule_loader/loader.py` | `RuleLoader.load()`: đọc file, lọc dòng, override, cô lập lỗi, thống kê, logging |
| `core_engine/rule_loader/__main__.py` | CLI `python -m core_engine.rule_loader` (thống kê, danh sách candidate, xuất JSONL) |
| `rules/rule_loader.json`, `rules/*.rules` | Cấu hình và rule mẫu của repository |

---

## 3. API và data contract

### 3.1 Cách dùng

```python
from core_engine.rule_loader import RuleLoader, RuleLoaderConfig

config = RuleLoaderConfig.from_json_file("rules/rule_loader.json")
result = RuleLoader(config).load()

for candidate in result.rules:          # giao cho mục 4.2
    parser_validator.parse(candidate)   # (parser_validator chưa được viết ở mục 4.1)
```

Có thể truyền callback thay vì vòng lặp; callback được gọi cho từng candidate:

```python
result = RuleLoader(config).load(handler=parser_validator.parse)
```

### 3.2 `RuleSourceEntry` (rule candidate)

| Field | Kiểu | Ý nghĩa |
| --- | --- | --- |
| `raw_text` | `str` | Nguyên văn dòng rule, chỉ bỏ ký tự xuống dòng. Không trim, không serialize lại |
| `source_file` | `str` | Đường dạng hiển thị, tương đối so với `base_dir` khi nằm trong `base_dir` |
| `path` | `str` | Đường dẫn tuyệt đối đã chuẩn hoá (truy vết) |
| `line_number` | `int` | Số dòng 1-based trong file |
| `rule_ref` | `str` | `<source_file>:<line_number>`, ví dụ `web.rules:5` — định danh nguồn ổn định |
| `file_index` | `int` | Vị trí file trong danh sách cấu hình (0-based) |
| `enabled` | `bool` | Trạng thái cuối; candidate trong `result.rules` luôn `True` |

`RuleSourceEntry` **không** có `valid`/`invalid`/`unsupported`: các trạng thái đó thuộc mục 4.2.

### 3.3 `RuleLoadResult`

| Field | Nội dung |
| --- | --- |
| `rules` | Danh sách candidate đã enable, đúng thứ tự file → dòng |
| `disabled_rules` | Candidate bị tắt bởi `rule_overrides` (`enabled=False`), để truy vết |
| `warnings` | Danh sách `RuleLoadWarning` (code, severity, message, source_file, line_number, rule_ref) |
| `statistics` | `RuleLoadStatistics` (xem 3.4) |
| `file_results` | `RuleFileSummary` cho từng file: loaded/skipped/error, số dòng, số rule |
| `errors` / `has_errors` | Chỉ các diagnostic severity `error` |

`result.to_dict()` trả về dict JSON-serializable (dùng cho JSONL/log).

### 3.4 Thống kê (mục 4.7)

`files_configured`, `files_loaded`, `files_disabled`, `files_failed`, `files_skipped_extension`,
`files_empty`, `lines_read`, `lines_skipped_blank`, `lines_skipped_comment`, `rules_read`,
`rules_disabled`, `rules_emitted`, `rules_forwarded`, `rules_failed`, `warnings`, `errors`.

### 3.5 Mã diagnostic

| Code | Severity | Khi nào |
| --- | --- | --- |
| `FILE_DISABLED` | info | File bị tắt trong cấu hình |
| `RULE_DISABLED` | info | Rule bị tắt bởi `rule_overrides` |
| `FILE_EMPTY` / `FILE_NO_RULES` | info | File rỗng / chỉ có comment + dòng trắng |
| `EXTENSION_NOT_ALLOWED` | warning | Sai phần mở rộng (strict: bỏ file; lenient: vẫn nạp) |
| `UNKNOWN_RULE_OVERRIDE` | warning | Selector không khớp rule nào (kể cả rule nằm trong file bị tắt) |
| `INVALID_CONFIG` | warning | Entry cấu hình lỗi, key lạ, override sai kiểu |
| `FILE_NOT_FOUND` | error | File không tồn tại |
| `FILE_NOT_REGULAR` | error | Đường dẫn là thư mục/không phải regular file |
| `FILE_UNREADABLE` | error | Không có quyền đọc |
| `FILE_ENCODING_ERROR` | error | Decode lỗi (policy `strict`) |
| `FILE_IO_ERROR` | error | Lỗi I/O khác |
| `CANDIDATE_HANDLER_ERROR` | error | Callback xử lý candidate raise exception |

---

## 4. Cấu hình enable/disable file và rule

### 4.1 Định dạng

Project chưa có dependency YAML và chưa có quy ước file cấu hình, nên dùng **JSON thuần
standard library** (`rules/rule_loader.json`):

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

### 4.2 Quy tắc và mặc định (đã cố định trong code + test)

| Quy tắc | Giá trị |
| --- | --- |
| Trạng thái mặc định của file | **enabled** (`enabled` bỏ trống ⇒ `true`) |
| Trạng thái mặc định của rule | **enabled** (chỉ tắt khi có override `false`) |
| Kiểu entry file | chuỗi path, hoặc object `{"path", "enabled"}` |
| Kiểu override | `false`/`true`, hoặc `{"enabled": bool}` |
| Precedence khi xung đột | **disabled thắng enabled** (kể cả khi 2 key cùng trỏ một rule_ref) |
| File bị tắt | không được đọc; override `true` bên trong **không** làm file được nạp lại (báo `UNKNOWN_RULE_OVERRIDE`) |
| Đường dẫn tương đối | resolve theo `base_dir`; mặc định `base_dir` = thư mục chứa file cấu hình (`from_json_file`), hoặc `cwd` khi cấu hình dựng bằng code |
| `rule_ref` | `<source_file>:<line>`; `source_file` tương đối theo `base_dir` ⇒ ổn định, không phụ thuộc `cwd` |
| Extension hợp lệ | `.rules` (`allowed_suffixes`) |
| Policy extension | `strict` (mặc định, bỏ file sai extension) / `lenient` (nạp kèm warning) |
| Encoding | UTF-8, `encoding_errors="strict"` (mặc định). `replace` là policy **có mất dữ liệu**, phải chọn tường minh |
| Cấu hình lỗi | entry lỗi → `INVALID_CONFIG` warning, các entry khác vẫn nạp; tài liệu JSON hỏng/không đúng cấu trúc → `RuleLoaderConfigError` (không âm thầm tắt toàn bộ rule) |

### 4.3 CLI

```bash
# Dùng cấu hình của repository
python -m core_engine.rule_loader --config rules/rule_loader.json --stats --list

# Ghi candidate ra JSONL cho bước sau
python -m core_engine.rule_loader --config rules/rule_loader.json \
    --output TEST/BT3/rule_loader/evidence/candidates.jsonl

# Nạp nhanh nhiều file, không cần file cấu hình
python -m core_engine.rule_loader --rules rules/web.rules --rules rules/local.rules --list
```

Exit code: `0` không có lỗi, `1` có ít nhất một error (file/candidate), `2` cấu hình không dùng được.

---

## 5. Fixtures

Thư mục `TEST/BT3/rule_loader/fixtures/`:

| File | Dùng cho | Nội dung |
| --- | --- | --- |
| `web.rules` | RL01, RL02, RL03, RL07, RL09, RL10, RL11 | 8 dòng: 3 comment (1 comment thụt lề), 2 dòng trắng, 3 rule; 1 rule có `#` trong `content` |
| `local.rules` | RL02, RL04, RL12, RL14 | 7 dòng: 2 comment, 1 dòng trắng, 3 rule; rule dòng 6 bị tắt bởi override |
| `hash_in_content.rules` | RL10 | 2 rule chứa `#` trong `msg`/`content`/`reference` |
| `empty.rules` | RL08 | File 0 byte |
| `comments_only.rules` | RL08 | 3 dòng, toàn comment (1 dòng thụt lề) |
| `wrong_extension.txt` | RL06 | 1 comment + 1 rule, sai extension |
| `invalid_utf8.rules` | RL13 | 1 comment + 1 rule chứa byte `0xFF 0xFE` (UTF-8 không hợp lệ) |
| `nested/deep.rules` | RL11 | 1 rule trong thư mục con, kiểm tra path tương đối |

Fixture dạng thư mục (`folder.rules`) và file không có quyền đọc được tạo tạm trong
`tempfile.TemporaryDirectory()` để test không phụ thuộc quyền của môi trường.

---

## 6. Cách chạy test

```bash
# Toàn bộ test Rule Loader (37 test)
.venv/bin/python -m unittest tests.test_rule_loader -v

# Toàn bộ test repository (91 test: 54 của Bài 1–2 + 37 của Bài 3 mục 4.1)
.venv/bin/python -m unittest discover -s tests -v
```

Chạy từng nhóm test (đúng lệnh đã dùng để tạo evidence):

| Case | Lệnh |
| --- | --- |
| RL01 | `.venv/bin/python -m unittest tests.test_rule_loader.RuleFileParsingTestCase -v` |
| RL02 | `.venv/bin/python -m unittest tests.test_rule_loader.MultiFileTestCase -v` |
| RL03 | `.venv/bin/python -m unittest tests.test_rule_loader.RuleFileEnableTestCase -v` |
| RL04 | `.venv/bin/python -m unittest tests.test_rule_loader.PerRuleEnableTestCase -v` |
| RL05 | `.venv/bin/python -m unittest tests.test_rule_loader.RuleFileErrorTestCase.test_missing_file_warns_and_continues tests.test_rule_loader.RuleFileErrorTestCase.test_directory_path_is_not_a_regular_file tests.test_rule_loader.RuleFileErrorTestCase.test_unreadable_file_is_reported -v` |
| RL06 | `.venv/bin/python -m unittest tests.test_rule_loader.RuleFileErrorTestCase.test_wrong_extension_is_skipped_by_strict_policy tests.test_rule_loader.RuleFileErrorTestCase.test_wrong_extension_is_loaded_by_lenient_policy -v` |
| RL07 | `.venv/bin/python -m unittest tests.test_rule_loader.CandidateHandlerTestCase -v` |
| RL08 | `.venv/bin/python -m unittest tests.test_rule_loader.EmptyFileTestCase -v` |
| RL09 | `.venv/bin/python -m unittest tests.test_rule_loader.CommentDetectionTestCase.test_comment_with_leading_whitespace_is_skipped -v` |
| RL10 | `.venv/bin/python -m unittest tests.test_rule_loader.CommentDetectionTestCase.test_hash_inside_rule_body_is_preserved -v` |
| RL11 | `.venv/bin/python -m unittest tests.test_rule_loader.RulePathTestCase -v` |
| RL12 | `.venv/bin/python -m unittest tests.test_rule_loader.RuleOverrideTestCase -v` |
| RL13 | `.venv/bin/python -m unittest tests.test_rule_loader.RuleLoaderConfigTestCase -v` |
| RL14 | `.venv/bin/python -m unittest tests.test_rule_loader.IsolationRegressionTestCase -v` |
| Cấu hình mẫu | `.venv/bin/python -m unittest tests.test_rule_loader.ShippedConfigTestCase -v` |

---

## 7. Kết quả thực tế RL01–RL14

Chạy ngày 2026-11-01, môi trường `.venv` (Python 3.14.4), WSL/Ubuntu.

| ID | Test class / method | Kết quả | Log |
| --- | --- | --- | --- |
| RL01 | `RuleFileParsingTestCase` (3 test) | **PASS** | `evidence/run_RL01_parse.log` |
| RL02 | `MultiFileTestCase` (2 test) | **PASS** | `evidence/run_RL02_multifile.log` |
| RL03 | `RuleFileEnableTestCase` (2 test) | **PASS** | `evidence/run_RL03_file_disable.log` |
| RL04 | `PerRuleEnableTestCase` (3 test) | **PASS** | `evidence/run_RL04_rule_disable.log` |
| RL05 | `RuleFileErrorTestCase` (3 test) | **PASS** | `evidence/run_RL05_missing_file.log` |
| RL06 | `RuleFileErrorTestCase` (2 test) | **PASS** | `evidence/run_RL06_extension.log` |
| RL07 | `CandidateHandlerTestCase` (1 test) | **PASS** | `evidence/run_RL07_handler_error.log` |
| RL08 | `EmptyFileTestCase` (2 test) | **PASS** | `evidence/run_RL08_empty_files.log` |
| RL09 | `CommentDetectionTestCase::test_comment_with_leading_whitespace_is_skipped` | **PASS** | `evidence/run_RL09_comment_whitespace.log` |
| RL10 | `CommentDetectionTestCase::test_hash_inside_rule_body_is_preserved` | **PASS** | `evidence/run_RL10_hash_in_rule.log` |
| RL11 | `RulePathTestCase` (4 test) | **PASS** | `evidence/run_RL11_relative_path.log` |
| RL12 | `RuleOverrideTestCase` (3 test) | **PASS** | `evidence/run_RL12_unknown_selector.log` |
| RL13 | `RuleLoaderConfigTestCase` (8 test) | **PASS** | `evidence/run_RL13_config_errors.log` |
| RL14 | `IsolationRegressionTestCase` (1 test) | **PASS** | `evidence/run_RL14_isolation.log` |
| — | `ShippedConfigTestCase` (1 test) | **PASS** | `evidence/run_shipped_config.log` |

Tổng: `Ran 37 tests ... OK` (`evidence/run_rule_loader_tests.log`), exit code 0.

### Chi tiết từng case

#### RL01 — File có rule, comment và dòng trắng

* Input: `fixtures/web.rules` (8 dòng).
* Assertion chính:
  * `refs == ["web.rules:4", "web.rules:6", "web.rules:8"]`.
  * `lines_read=8`, `lines_skipped_blank=2`, `lines_skipped_comment=3`, `rules_read=3`, `rules_emitted=3`.
  * `raw_text` khớp nguyên văn dòng 4; `source_file="web.rules"`, `line_number=4`, `path` tuyệt đối, `file_index=0`, `enabled=True`.
  * `test_raw_text_is_not_rewritten`: file CRLF có trailing spaces → `raw_text` giữ trailing spaces, không còn `\r`.
  * `test_result_is_json_serializable`: `json.dumps(result.to_dict())` chạy được, đếm đúng 6 rule/2 file.
* Kết quả: `Ran 3 tests ... OK`.

#### RL02 — Nạp nhiều file rules

* Input: `web.rules` + `local.rules` (và thứ tự đảo).
* Assertion: 6 candidate đúng thứ tự `web.rules:4,6,8 → local.rules:4,6,7`; `file_index = [0,0,0,1,1,1]`; `source_file` không trộn; đảo thứ tự cấu hình thì candidate đầu là `local.rules:4`.
* Kết quả: `Ran 2 tests ... OK`.

#### RL03 — File bị disable

* Input: `[{"path": "web.rules", "enabled": true}, {"path": "local.rules", "enabled": false}]`.
* Assertion: chỉ còn 3 candidate của `web.rules`; `files_configured=2`, `files_disabled=1`, `files_loaded=1`; `file_results[1].skipped_reason == "disabled"`, `rules_read=0`; warning `FILE_DISABLED` severity `info`. Test thứ hai xác nhận mặc định là enabled.
* Kết quả: `Ran 2 tests ... OK`.

#### RL04 — Disable một rule riêng lẻ

* Input: `local.rules` + `{"local.rules:6": false}`.
* Assertion: còn `local.rules:4`, `local.rules:7`; `rules_read=3`, `rules_disabled=1`, `rules_emitted=2`; `disabled_rules == ["local.rules:6"]` với `enabled=False`; warning `RULE_DISABLED` đúng `rule_ref`/`line_number`.
* Test bổ trợ: override `true` không làm mất rule và không sinh `UNKNOWN_RULE_OVERRIDE`; cấu hình JSON đọc từ file cho kết quả `["web.rules:4", "web.rules:8"]`.
* Kết quả: `Ran 3 tests ... OK`.

#### RL05 — File không tồn tại / không phải file / không có quyền đọc

* Input: `["missing.rules", "web.rules"]`.
* Assertion: 3 candidate của `web.rules` vẫn nạp; `files_failed=1`; warning `FILE_NOT_FOUND` severity `error` có `source_file` và message chứa đường dẫn; `has_errors=True`.
* Bổ trợ: thư mục tên `folder.rules` → `FILE_NOT_REGULAR`; file `chmod 000` → `FILE_UNREADABLE` (test tự skip nếu chạy bằng root).
* Kết quả: `Ran 3 tests ... OK` (không skip trên máy chạy thực tế).

#### RL06 — File sai extension

* Policy `strict` (mặc định): `wrong_extension.txt` bị bỏ, `rules=[]`, `files_skipped_extension=1`, warning `EXTENSION_NOT_ALLOWED` nêu policy strict.
* Policy `lenient`: nạp `wrong_extension.txt:2` và vẫn có warning.
* Kết quả: `Ran 2 tests ... OK`.

#### RL07 — Candidate processing error

* Test double raise `RuntimeError("parser double failed")` khi gặp `web.rules:6`.
* Assertion: handler được gọi cho cả 3 candidate theo thứ tự; `rules_forwarded=2`, `rules_failed=1`; warning `CANDIDATE_HANDLER_ERROR` có `rule_ref`, `source_file`, `line_number`, tên exception; candidate vẫn nằm trong `result.rules` (lỗi thuộc bước chuyển tiếp, không phải bước nạp).
* Kết quả: `Ran 1 test ... OK`.

#### RL08 — File rỗng hoặc chỉ có comment

* `empty.rules`: `rules=[]`, `files_loaded=1`, `files_empty=1`, `lines_read=0`, warning `FILE_EMPTY` (info), `has_errors=False`.
* `comments_only.rules`: `lines_read=3`, `lines_skipped_comment=3`, warning `FILE_NO_RULES` (info).
* Kết quả: `Ran 2 tests ... OK`.

#### RL09 — Comment có whitespace phía trước

* `web.rules` dòng 5 (`    # RL09 fixture...`) không sinh candidate (`web.rules:5` không có trong `refs`), vẫn được tính vào `lines_skipped_comment=3`.
* Kết quả: `Ran 1 test ... OK`.

#### RL10 — Ký tự `#` bên trong nội dung rule

* `hash_in_content.rules`: 2 candidate `:2`, `:3`; `raw_text` giữ nguyên `msg:"hash # in message"`, `content:"a#b"`, `reference:cve,2024#1`.
* Kết quả: `Ran 1 test ... OK`.

#### RL11 — Relative path

* `base_dir=REPO_ROOT`, path `TEST/BT3/rule_loader/fixtures/web.rules` → `rule_ref = TEST/BT3/rule_loader/fixtures/web.rules:4`.
* `test_rule_ref_does_not_depend_on_working_directory`: `os.chdir()` sang tempdir rồi load lại với cùng `base_dir` → `rule_ref` và `path` tuyệt đối không đổi.
* Đường dẫn tuyệt đối nằm trong `base_dir` → `rule_ref` tương đối (`web.rules:4`); path lồng nhau → `nested/deep.rules:2`.
* Kết quả: `Ran 4 tests ... OK`.

#### RL12 — Rule selector không tồn tại

* `{"web.rules:999": false}` → 3 rule vẫn nạp, `rules_disabled=0`, warning `UNKNOWN_RULE_OVERRIDE` với `rule_ref=web.rules:999`.
* Override `true` cho rule trong file bị disable → file **không** được nạp, có warning `UNKNOWN_RULE_OVERRIDE`.
* Selector `./local.rules:6` được chuẩn hoá và vẫn khớp (`rules_disabled=1`).
* Kết quả: `Ran 3 tests ... OK`.

#### RL13 — Lỗi cấu hình

* `[{"enabled": false}, "web.rules"]` → entry lỗi thành `INVALID_CONFIG` warning, `web.rules` vẫn nạp 3 candidate (`files_configured=1`).
* `{"local.rules:6": "no"}` → `INVALID_CONFIG`, 3 rule vẫn nạp (không âm thầm disable).
* Key lạ (`rule_file`) → `INVALID_CONFIG`.
* Tài liệu không dùng được (`["web.rules"]`, `rule_files` là string, `rule_overrides` là list) → `RuleLoaderConfigError` (fail rõ ràng, không load nửa vời).
* JSON hỏng → `RuleLoaderConfigError` nêu đường dẫn + dòng/cột; file cấu hình không tồn tại → lỗi nêu đường dẫn.
* Byte UTF-8 không hợp lệ: policy `strict` → `FILE_ENCODING_ERROR`, file bị loại, **không** candidate nửa vời nào lọt ra; policy `replace` → nạp được nhưng `raw_text` chứa `U+FFFD` (mất dữ liệu có chủ đích, tường minh).
* Kết quả: `Ran 8 tests ... OK`.

#### RL14 — Regression / isolation

* Input: `["missing.rules", "invalid_utf8.rules", "web.rules", "local.rules"]`, override tắt `local.rules:6`, handler raise ở `web.rules:4`.
* Assertion: 5 candidate đúng thứ tự; handler nhận đủ 5; `files_configured=4`, `files_loaded=2`, `files_failed=2`, `rules_read=6`, `rules_disabled=1`, `rules_emitted=5`, `rules_forwarded=4`, `rules_failed=1`, `errors=3`, `has_errors=True`.
* Kết quả: `Ran 1 test ... OK`.

#### Cấu hình mẫu của repository

* `rules/rule_loader.json` → 5 candidate (`web.rules:5,7,9`, `local.rules:4,8`), `files_disabled=1` (`dos.rules`), `rules_disabled=1` (`local.rules:7`), `has_errors=False`; chỉ có diagnostic `FILE_DISABLED` và `RULE_DISABLED` (info).
* Kết quả: `Ran 1 test ... OK`; CLI thật (`evidence/run_cli_default.log`) cho cùng kết quả, exit code 0.

---

## 8. Vì sao từng tiêu chí đạt

| Tiêu chí (đề bài) | Cơ chế trong code | Test chứng minh |
| --- | --- | --- |
| Đọc 1 hoặc nhiều file, giữ thứ tự file và rule | `load()` lặp `files` theo thứ tự cấu hình, `_read_file()` đọc tuần tự bằng `enumerate` | RL02 |
| Bỏ qua dòng trắng | `if not text.strip(): lines_skipped_blank += 1` | RL01, RL08 |
| Bỏ qua comment, cho phép whitespace trước `#` | `if text.lstrip().startswith("#")` | RL01, RL09 |
| Không cắt `#` trong rule | Chỉ kiểm tra ký tự không-trắng đầu tiên; `raw_text` không bị sửa | RL10 |
| Không thay đổi nội dung rule | Chỉ `rstrip("\r\n")`; test CRLF + trailing spaces | RL01 |
| Lưu metadata nguồn | `RuleSourceEntry(source_file, path, line_number, rule_ref, file_index)` | RL01, RL02, RL11 |
| File lỗi không dừng loader | Mỗi file trong `try/except` riêng, lỗi → warning + `continue` | RL05, RL14 |
| File rỗng/comment-only không phải lỗi | `FILE_EMPTY`/`FILE_NO_RULES` severity `info`, `has_errors=False` | RL08 |
| Encoding rõ ràng | UTF-8 mặc định, `encoding_errors="strict"`; policy `replace` phải chọn tường minh | RL13 |
| Không nuốt exception | Mọi `OSError`/`UnicodeDecodeError` được map thành code + message có đường dẫn | RL05, RL13 |
| Enable/disable file bằng cấu hình | `RuleFileConfig.enabled`, file bị tắt không được mở | RL03, RL12 |
| Enable/disable rule bằng cấu hình | `rule_overrides[rule_ref]`, disabled thắng enabled | RL04, RL12 |
| Selector không tồn tại có warning | Tập `matched_overrides` so với `overrides` | RL12 |
| Interface bàn giao | `RuleLoadResult.rules` / `handler` callback | RL07, `ShippedConfigTestCase` |
| Cô lập lỗi từng candidate | `_forward()` bọc `handler(entry)` trong `try/except` | RL07, RL14 |
| Thống kê đầy đủ | `RuleLoadStatistics` + `RuleFileSummary` | RL01, RL03, RL04, RL14 |
| Không phụ thuộc Scapy/Flow Tracker | `core_engine/rule_loader/*` chỉ import stdlib | (import graph, không import `scapy`) |
| Không hard-code rule | Rule chỉ nằm trong `rules/*.rules` và fixture | `ShippedConfigTestCase` |

---

## 9. Evidence

| Nội dung | Đường dẫn |
| --- | --- |
| Test Rule Loader đầy đủ | `evidence/run_rule_loader_tests.log` (`Ran 37 tests ... OK`) |
| Regression toàn repository | `evidence/run_full_suite.log` (`Ran 91 tests ... OK`) |
| Log từng RL01–RL14 | `evidence/run_RL01_parse.log` … `evidence/run_RL14_isolation.log` |
| Cấu hình mẫu | `evidence/run_shipped_config.log` |
| CLI mặc định (stats + list) | `evidence/run_cli_default.log` (exit 0) |
| CLI xuất JSONL | `evidence/run_cli_jsonl.log` + `evidence/candidates.jsonl` |
| CLI lỗi cấu hình không tồn tại | `evidence/run_cli_missing_config.log` (exit 2) |
| CLI lỗi JSON hỏng | `evidence/run_cli_broken_json.log` (exit 2) |
| CLI lỗi một file rule | `evidence/run_cli_missing_rule_file.log` (exit 1, 3 candidate vẫn nạp) |

Log được tạo bằng cách chạy thật lệnh và ghi lại `stdout + stderr + exit code`:

```bash
.venv/bin/python -m unittest tests.test_rule_loader -v
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m core_engine.rule_loader --config rules/rule_loader.json --stats --list
```

Không có log nào được viết tay hay chỉnh sửa sau khi chạy.

---

## 10. Hạn chế còn lại

1. **Chưa parse Snort rule** (đúng phạm vi 4.1): `rule_ref` dựa trên dòng, nên khi chèn/xoá dòng
   trong file thì `rule_overrides` phải cập nhật lại. Sau mục 4.2 có thể bổ sung selector theo SID
   mà không phải viết lại loader.
2. **Không có repository/index** (4.3), không dedup rule trùng, không xử lý directive `include`
   của Snort.
3. **Không hot-reload**: sửa file rule phải gọi `load()` lại.
4. File ngoài `base_dir` được hiển thị bằng đường dẫn tuyệt đối ⇒ `rule_ref` không portable
   giữa các máy. Trong repo, cấu hình đặt cạnh rule nên `rule_ref` ổn định (`web.rules:5`).
5. `encoding_errors="replace"` là policy **mất dữ liệu**; mặc định `strict` để không âm thầm
   biến đổi nội dung.
6. File được đọc toàn bộ vào bộ nhớ; phù hợp với file rule thông thường, chưa tối ưu cho file
   rất lớn.
7. Với file lỗi encoding, `lines_read` chỉ đếm các dòng đã decode thành công trước khi lỗi.
8. Đường dẫn Windows (khác ổ đĩa) có nhánh xử lý riêng nhưng chưa được test trên Windows.
9. Chưa tích hợp Rule Loader vào `main.py` của pipeline Bài 1–2 (cố ý, để không đổi hành vi
   CLI cũ); loader có CLI riêng `python -m core_engine.rule_loader`.

---

## 11. Xác nhận phạm vi

* Đã hoàn thành **đến hết mục 4.1 — Rule Loader**: đọc nhiều file `.rules`, lọc comment/dòng
  trắng, enable/disable file và rule bằng cấu hình, cô lập lỗi, thống kê, logging, data contract
  bàn giao cho mục 4.2, test RL01–RL14, report và README.
* **Chưa** triển khai 4.2 Rule Parser & Validator, 4.3 Rule Repository/Indexer,
  4.4 Rule Matching Engine, 4.5 Rule Evaluation Engine, 4.6 Detection Event Generator,
  cũng như alert/logging/response của các bài sau.
* Không thay đổi hành vi pipeline Bài 1–2: toàn bộ 54 test cũ vẫn PASS
  (`evidence/run_full_suite.log`, tổng 91 test).
