# TEST/BT3 — Bài tập 3 (Core Engine)

Thư mục này chứa fixture, bằng chứng chạy test và report cho **Bài tập 3**:

- **4.1 Rule Loader** (đã có từ trước, giữ nguyên)
- **4.2 Rule Parser & Validator**
- **4.3 Rule Repository / Indexer**
- **4.4 Rule Matching Engine**
- **4.5 Rule Evaluation Engine**
- **4.6 Detection Event Generator**

## 1. Report và bằng chứng

| Nội dung | Đường dẫn |
| --- | --- |
| Report 4.1 Rule Loader | [`rule_loader/REPORT_RULE_LOADER.md`](rule_loader/REPORT_RULE_LOADER.md) |
| Report TC01–TC14 (4.2–4.6) | [`reports/README.md`](reports/README.md) |
| Test log thật | `evidence/test_logs/` |
| JSONL output thật | `evidence/jsonl/` |
| Log CLI / môi trường | `evidence/other/` |
| Rule fixture | `rules/*.rules` |

## 2. Bảng testcase 4.2–4.6 (TC01–TC14)

| ID | Tình huống | Test class | Kết quả | Log |
| --- | --- | --- | --- | --- |
| TC01 | Loader → Parser → Pipeline → Detection | `TC01LoaderIntegrationTestCase`, `PipelineIntegrationTestCase` | PASS | `run_TC01_loader.log`, `run_TC01_pipeline.log` |
| TC02 | Rule sai cú pháp, rule sau vẫn parse | `TC02InvalidRuleTestCase` | PASS | `run_TC02.log` |
| TC03 | Keyword ngoài phạm vi | `TC03UnsupportedKeywordTestCase` | PASS | `run_TC03.log` |
| TC04 | Header any/IPv4/CIDR/port/range/hướng | `TC04HeaderParsingTestCase` | PASS | `run_TC04.log` |
| TC05 | `->` một chiều, `<>` hai chiều | `TC05DirectionTestCase` | PASS | `run_TC05.log` |
| TC06 | Indexer candidate | `TC06IndexerTestCase` | PASS | `run_TC06.log` |
| TC07 | Header short-circuit | `TC07HeaderShortCircuitTestCase` | PASS | `run_TC07.log` |
| TC08 | `flow:` từ tracker adapter | `TC08FlowStateTestCase` | PASS | `run_TC08.log` |
| TC09 | `content` / `nocase` | `TC09ContentNocaseTestCase` | PASS | `run_TC09.log` |
| TC10 | `offset` / `depth` | `TC10OffsetDepthTestCase` | PASS | `run_TC10.log` |
| TC11 | `distance` / `within` + backtracking | `TC11DistanceWithinTestCase` | PASS | `run_TC11.log` |
| TC12 | TCP `flags` + `dsize` | `TC12FlagsDsizeTestCase` | PASS | `run_TC12.log` |
| TC13 | Nhiều match ⇒ nhiều detection | `TC13MultipleMatchesTestCase` | PASS | `run_TC13.log` |
| TC14 | Schema Detection Event | `TC14DetectionEventTestCase` | PASS | `run_TC14.log` |

Test bổ sung: `ParserOptionContractTestCase`, `RepositoryDiagnosticsTestCase`,
`EvaluationStatisticsAndIsolationTestCase` (log `run_contract_*.log`).

**Kết quả thật:** 63/63 test Assignment 3 PASS; 154/154 test toàn repository PASS
(91 test Bài 1–2 + 4.1, 63 test 4.2–4.6). Xem `evidence/test_logs/run_assignment3_suite.log`
và `run_full_suite.log`.

## 3. Rule fixture

| File | Dùng cho |
| --- | --- |
| `loading.rules` | TC01 |
| `header_rules.rules`, `header_invalid.rules` | TC04, TC06 |
| `invalid_rules.rules` | TC02 |
| `unsupported_rules.rules` | TC03 |
| `direction_rules.rules` | TC05 |
| `content_rules.rules` | TC09, TC10, TC11 |
| `flags_dsize.rules`, `flags_invalid.rules` | TC12 |
| `flow_rules.rules`, `flow_invalid.rules` | TC08 |
| `multi_match.rules` | TC13 |
| `detection_rules.rules` | TC14 |
| `modifiers_invalid.rules`, `dsize_invalid.rules` | Option contract |
| `duplicate_sid.rules` | Duplicate SID policy |
| `quoted.rules`, `required.rules` | Parser contract |
| `smoke.rules` | CLI/PCAP end-to-end |
| `bt3_rules.json` | Cấu hình loader cho smoke |

## 4. Lệnh tái hiện

```bash
# Toàn bộ test Bài tập 3
.venv/bin/python -m unittest tests.test_assignment3_parser \
    tests.test_assignment3_repository tests.test_assignment3_matching \
    tests.test_assignment3_evaluation tests.test_assignment3_pipeline -v

# Toàn bộ repository (Bài 1–2 + Bài 3)
.venv/bin/python -m unittest discover -s tests -v

# Rule Loader (4.1)
.venv/bin/python -m unittest tests.test_rule_loader -v

# CLI end-to-end với rule thật
.venv/bin/python main.py --pcap TEST/assignment_2/input_mixed.pcap \
    --rules TEST/BT3/rules/smoke.rules \
    --output output/events.jsonl \
    --flows-output output/flows.jsonl \
    --detections-output output/detections.jsonl

# Tạo lại toàn bộ JSONL/log bằng chứng
.venv/bin/python tests/generate_bt3_evidence.py
```

## 5. Evidence chi tiết

| File | Nội dung |
| --- | --- |
| `evidence/test_logs/run_TC01_loader.log` … `run_TC14.log` | Log riêng từng testcase, có `# exit code: 0` |
| `evidence/test_logs/run_contract_*.log` | Test contract bổ sung |
| `evidence/test_logs/run_assignment3_suite.log` | 63 test Assignment 3, `OK` |
| `evidence/test_logs/run_full_suite.log` | 154 test toàn repository, `OK` |
| `evidence/jsonl/parse_results_all_rules.jsonl` | 67 parse result thật (45 valid, 17 invalid, 5 unsupported) |
| `evidence/jsonl/repository_diagnostics.jsonl` | 23 diagnostic thật (gồm 1 duplicate SID) |
| `evidence/jsonl/candidate_selection.jsonl` | 4 truy vấn index thật |
| `evidence/jsonl/smoke_detections.jsonl` | 3 detection thật từ PCAP |
| `evidence/jsonl/smoke_events.jsonl`, `smoke_flows.jsonl` | 15 event + 7 flow thật |
| `evidence/jsonl/no_rules_events.jsonl`, `no_rules_flows.jsonl` | Chạy không rule, giữ hành vi Bài 2 |
| `evidence/other/run_cli_smoke.log` | CLI có rule, exit 0 |
| `evidence/other/run_cli_no_rules.log` | CLI không rule, exit 0 |

## 6. Ghi chú

- Không có report/log nào được viết tay thay cho kết quả chạy; mọi log đều do
  `unittest`/CLI sinh ra và có dòng exit code.
- Artifact Bài tập 1 (`TEST/tcp_handshake/`, …) và Bài tập 2 (`TEST/assignment_2/`)
  được giữ nguyên.
- Report 4.1 vẫn nằm ở `rule_loader/`; report 4.2–4.6 nằm ở `reports/`.
