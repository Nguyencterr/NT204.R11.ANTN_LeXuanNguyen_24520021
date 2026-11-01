# TEST/BT3 — Bài tập 3 (Core Engine), mục 4.1 Rule Loader

Thư mục này chứa fixture, bằng chứng chạy test và report cho **Bài tập 3, mục 4.1 Rule Loader**.

* **Report chi tiết:** [`rule_loader/REPORT_RULE_LOADER.md`](rule_loader/REPORT_RULE_LOADER.md)
* **Phạm vi:** chỉ 4.1. Mục 4.2–4.6 **chưa triển khai**.
* **Code:** `core_engine/rule_loader/` (`models.py`, `config.py`, `loader.py`, `__main__.py`)
* **Cấu hình + rule mẫu:** `rules/rule_loader.json`, `rules/web.rules`, `rules/local.rules`, `rules/dos.rules`
* **Test:** `tests/test_rule_loader.py`
* **Fixture:** `rule_loader/fixtures/`
* **Evidence:** `rule_loader/evidence/`

## 1. Bảng testcase

| ID | Tình huống | Test class / method | Trạng thái | Evidence |
| --- | --- | --- | --- | --- |
| RL01 | File có rule, comment, dòng trắng | `RuleFileParsingTestCase` (3 test) | PASS | `rule_loader/evidence/run_RL01_parse.log` |
| RL02 | Nạp nhiều file, giữ thứ tự | `MultiFileTestCase` (2 test) | PASS | `rule_loader/evidence/run_RL02_multifile.log` |
| RL03 | File bị disable | `RuleFileEnableTestCase` (2 test) | PASS | `rule_loader/evidence/run_RL03_file_disable.log` |
| RL04 | Disable một rule riêng lẻ | `PerRuleEnableTestCase` (3 test) | PASS | `rule_loader/evidence/run_RL04_rule_disable.log` |
| RL05 | File không tồn tại / không phải file / không đọc được | `RuleFileErrorTestCase` (3 test) | PASS | `rule_loader/evidence/run_RL05_missing_file.log` |
| RL06 | File sai extension | `RuleFileErrorTestCase` (2 test) | PASS | `rule_loader/evidence/run_RL06_extension.log` |
| RL07 | Candidate processing error | `CandidateHandlerTestCase` (1 test) | PASS | `rule_loader/evidence/run_RL07_handler_error.log` |
| RL08 | File rỗng / chỉ comment | `EmptyFileTestCase` (2 test) | PASS | `rule_loader/evidence/run_RL08_empty_files.log` |
| RL09 | Comment có whitespace phía trước | `CommentDetectionTestCase::test_comment_with_leading_whitespace_is_skipped` | PASS | `rule_loader/evidence/run_RL09_comment_whitespace.log` |
| RL10 | `#` bên trong nội dung rule | `CommentDetectionTestCase::test_hash_inside_rule_body_is_preserved` | PASS | `rule_loader/evidence/run_RL10_hash_in_rule.log` |
| RL11 | Relative path | `RulePathTestCase` (4 test) | PASS | `rule_loader/evidence/run_RL11_relative_path.log` |
| RL12 | Selector không tồn tại | `RuleOverrideTestCase` (3 test) | PASS | `rule_loader/evidence/run_RL12_unknown_selector.log` |
| RL13 | Lỗi cấu hình / encoding | `RuleLoaderConfigTestCase` (8 test) | PASS | `rule_loader/evidence/run_RL13_config_errors.log` |
| RL14 | Regression / isolation | `IsolationRegressionTestCase` (1 test) | PASS | `rule_loader/evidence/run_RL14_isolation.log` |
| — | Cấu hình mẫu `rules/rule_loader.json` | `ShippedConfigTestCase` (1 test) | PASS | `rule_loader/evidence/run_shipped_config.log` |

Tổng: **37/37 PASS**. Regression toàn repository: **91/91 PASS**.

## 2. Lệnh tái hiện

```bash
# Toàn bộ test Rule Loader
.venv/bin/python -m unittest tests.test_rule_loader -v

# Toàn bộ test repository (Bài 1–2 + Bài 3 mục 4.1)
.venv/bin/python -m unittest discover -s tests -v

# CLI với cấu hình mẫu
.venv/bin/python -m core_engine.rule_loader --config rules/rule_loader.json --stats --list

# CLI xuất candidate JSONL
.venv/bin/python -m core_engine.rule_loader --config rules/rule_loader.json \
    --output TEST/BT3/rule_loader/evidence/candidates.jsonl
```

## 3. Evidence

| File | Nội dung |
| --- | --- |
| `rule_loader/evidence/run_rule_loader_tests.log` | 37 test Rule Loader, `OK`, exit 0 |
| `rule_loader/evidence/run_full_suite.log` | 91 test toàn repository, `OK`, exit 0 |
| `rule_loader/evidence/run_RL01_*.log` … `run_RL14_*.log` | Log riêng từng testcase |
| `rule_loader/evidence/run_cli_default.log` | CLI: 5 candidate, `dos.rules` bị tắt, exit 0 |
| `rule_loader/evidence/run_cli_missing_rule_file.log` | Một file rule thiếu: 3 candidate vẫn nạp, exit 1 |
| `rule_loader/evidence/run_cli_missing_config.log` | Cấu hình không tồn tại, exit 2 |
| `rule_loader/evidence/run_cli_broken_json.log` | JSON hỏng (báo dòng/cột), exit 2 |
| `rule_loader/evidence/candidates.jsonl` | Output JSONL thật của loader (5 dòng) |

## 4. Fixture

| File | Dùng cho |
| --- | --- |
| `rule_loader/fixtures/web.rules` | RL01, RL02, RL03, RL07, RL09, RL10, RL11 |
| `rule_loader/fixtures/local.rules` | RL02, RL04, RL12, RL14 |
| `rule_loader/fixtures/hash_in_content.rules` | RL10 |
| `rule_loader/fixtures/empty.rules` | RL08 |
| `rule_loader/fixtures/comments_only.rules` | RL08 |
| `rule_loader/fixtures/wrong_extension.txt` | RL06 |
| `rule_loader/fixtures/invalid_utf8.rules` | RL13 (byte `0xFF 0xFE`) |
| `rule_loader/fixtures/nested/deep.rules` | RL11 |

## 5. Ghi chú

* Không có test nào kiểm tra cú pháp Snort: mục 4.1 không parse rule, mục 4.2 mới làm việc đó.
* Các artifact của Bài tập 1 (`TEST/tcp_handshake/`, …) và Bài tập 2 (`TEST/assignment_2/`)
  được giữ nguyên, không bị thay đổi bởi Bài tập 3.
