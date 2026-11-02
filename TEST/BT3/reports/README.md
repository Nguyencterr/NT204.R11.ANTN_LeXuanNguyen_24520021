# Bài tập 3 — Báo cáo testcase TC01–TC14

Mỗi file dưới đây là báo cáo cho một testcase của Bài tập 3 (mục 4.2–4.6), kèm
mục tiêu, fixture, tiêu chí PASS, kết quả chạy thật và đường dẫn bằng chứng.

| ID | Tình huống | Kết quả | Report | Log |
| --- | --- | --- | --- | --- |
| TC01 | Loader → Parser → Pipeline → Detection end-to-end | PASS | [TC01](TC01_loader_pipeline.md) | `run_TC01_loader.log`, `run_TC01_pipeline.log` |
| TC02 | Rule sai cú pháp bị invalid, rule sau vẫn parse | PASS | [TC02](TC02_invalid_rules.md) | `run_TC02.log` |
| TC03 | Keyword ngoài phạm vi bị unsupported | PASS | [TC03](TC03_unsupported_rules.md) | `run_TC03.log` |
| TC04 | Header any/IPv4/CIDR/port/range/hướng | PASS | [TC04](TC04_header_parsing.md) | `run_TC04.log` |
| TC05 | `->` một chiều, `<>` hai chiều | PASS | [TC05](TC05_direction.md) | `run_TC05.log` |
| TC06 | Indexer không bỏ sót candidate | PASS | [TC06](TC06_indexer.md) | `run_TC06.log` |
| TC07 | Header mismatch short-circuit | PASS | [TC07](TC07_header_short_circuit.md) | `run_TC07.log` |
| TC08 | `flow:` từ tracker adapter | PASS | [TC08](TC08_flow_conditions.md) | `run_TC08.log` |
| TC09 | `content` / `nocase` | PASS | [TC09](TC09_content_nocase.md) | `run_TC09.log` |
| TC10 | `offset` / `depth` | PASS | [TC10](TC10_offset_depth.md) | `run_TC10.log` |
| TC11 | `distance` / `within` + backtracking | PASS | [TC11](TC11_distance_within.md) | `run_TC11.log` |
| TC12 | TCP `flags` và `dsize` | PASS | [TC12](TC12_flags_dsize.md) | `run_TC12.log` |
| TC13 | Nhiều match ⇒ nhiều detection | PASS | [TC13](TC13_multiple_matches.md) | `run_TC13.log` |
| TC14 | Schema Detection Event | PASS | [TC14](TC14_detection_event.md) | `run_TC14.log` |

## Test bổ sung ngoài TC01–TC14

| Nhóm | Test class | Log |
| --- | --- | --- |
| Option contract của parser | `ParserOptionContractTestCase` | `run_contract_parser.log` |
| Duplicate SID + diagnostic repository | `RepositoryDiagnosticsTestCase` | `run_contract_repository.log` |
| Thống kê + cô lập lỗi evaluation | `EvaluationStatisticsAndIsolationTestCase` | `run_contract_evaluation.log` |

## Tổng hợp

- Assignment 3: **63/63 PASS** (`run_assignment3_suite.log`).
- Toàn repository: **154/154 PASS** (`run_full_suite.log`), gồm 91 test Bài 1–2 + mục 4.1
  và 63 test mục 4.2–4.6.
- Tất cả log được tạo bằng cách chạy thật, có dòng `# exit code: 0`.

## Tái tạo bằng chứng

```bash
.venv/bin/python -m unittest tests.test_assignment3_parser \
    tests.test_assignment3_repository tests.test_assignment3_matching \
    tests.test_assignment3_evaluation tests.test_assignment3_pipeline -v
.venv/bin/python tests/generate_bt3_evidence.py
```
