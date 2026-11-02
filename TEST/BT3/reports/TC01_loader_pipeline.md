# TC01 — Loader → Parser → Repository → Pipeline end-to-end

- **Mục:** 4.1 (đã có) được nối với 4.2–4.6.
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_pipeline.TC01LoaderIntegrationTestCase`,
  `tests.test_assignment3_pipeline.PipelineIntegrationTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_pipeline.TC01LoaderIntegrationTestCase -v
.venv/bin/python -m unittest tests.test_assignment3_pipeline.PipelineIntegrationTestCase -v
```

- **Kết quả thực tế:**

```text
TC01LoaderIntegrationTestCase: Ran 1 test ... OK
PipelineIntegrationTestCase:   Ran 3 tests ... OK
```

## Mục tiêu

Chứng minh chỉ comment/dòng trắng bị bỏ qua, candidate giữ đúng thứ tự và metadata
nguồn; đồng thời chạy đúng một pipeline duy nhất
`PCAP → Parser → Decoder → Preprocessor → Tracker → Rule Engine → Detection JSONL`.

## Fixture / input

| Thành phần | Đường dẫn |
| --- | --- |
| Rule loader | `TEST/BT3/rules/loading.rules` |
| Smoke rules | `TEST/BT3/rules/smoke.rules` |
| PCAP | `TEST/assignment_2/input_mixed.pcap` |

## Tiêu chí PASS

1. `loading.rules` sinh đúng 3 candidate tại dòng 2, 4, 6, `rule_ref` ổn định.
2. Không có comment/dòng trắng nào đi tới parser.
3. PCAP chạy qua pipeline tạo 3 Detection Event với SID `4101001`, `4101002`, `4101003`.
4. Mỗi detection có `flow_id` và `matched_info`; serialize/deserialize JSON giữ nguyên.
5. Chạy pipeline **không** có rule giữ nguyên hành vi Assignment 2 (cùng số event/flow,
   không sinh detection).
6. Detection JSONL hợp lệ, mỗi dòng là một JSON object.

## Kết quả thực tế

- `loading.rules`: 3 candidate, cả 3 `valid`, SID `4100001/4100002/4100003`.
- PCAP: 15 packet, 15 event, 7 flow finalize, 3 detection.
- Detection: SQLi URI (SID 4101001), XSS body đã decode HTML entity (SID 4101002),
  DNS `example.com` (SID 4101003).
- `events_evaluated=15`, `candidate_rules=5`, `matches=3`, `no_match_count=2`,
  `errors=0`, `detections_generated=3`.
- Chạy không rule: 15 event, 7 flow, 0 detection.

## Bằng chứng

| File | Nội dung |
| --- | --- |
| `TEST/BT3/evidence/test_logs/run_TC01_loader.log` | 1 test loader, OK, exit 0 |
| `TEST/BT3/evidence/test_logs/run_TC01_pipeline.log` | 3 test pipeline, OK, exit 0 |
| `TEST/BT3/evidence/jsonl/smoke_events.jsonl` | 15 event thật |
| `TEST/BT3/evidence/jsonl/smoke_flows.jsonl` | 7 flow thật |
| `TEST/BT3/evidence/jsonl/smoke_detections.jsonl` | 3 detection thật |
| `TEST/BT3/evidence/other/run_cli_smoke.log` | CLI smoke, exit 0 |
| `TEST/BT3/evidence/other/run_cli_no_rules.log` | CLI không rule, exit 0 |

## Ghi chú

- `smoke.rules` dùng `<>` cho rule XSS vì phản hồi HTTP đi từ server port 8080 về client;
  điều này kiểm tra đúng ngữ nghĩa hai chiều thay vì nới lỏng kiểm tra hướng.
- Toàn bộ artifact trên được tạo lại bằng `tests/generate_bt3_evidence.py`.
