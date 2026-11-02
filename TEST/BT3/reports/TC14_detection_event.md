# TC14 — Detection Event có đủ trường và metadata giải thích match

- **Mục:** 4.6 Detection Event Generator
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_evaluation.TC14DetectionEventTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_evaluation.TC14DetectionEventTestCase -v
```

- **Kết quả thực tế:** `Ran 4 tests ... OK`, exit 0.

## Mục tiêu

Mỗi match sinh một Detection Event JSON-compatible, có schema ổn định và đủ thông tin
truy vết: rule nào, event nào, flow nào, hướng nào, content khớp ở đâu.

## Fixture / input

`TEST/BT3/rules/detection_rules.rules` (SID `4100901`, `rev:3`) và event HTTP tổng hợp
có URI đã decode `q=' OR 1=1`.

## Schema kiểm tra

Các trường bắt buộc:

`schema_version`, `timestamp`, `packet_id`, `action`, `sid`, `rev`, `msg`,
`priority`, `classtype`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`,
`application_protocol`, `flow_id`, `matched_info`, `rule`.

`matched_info` gồm: `orientation`, `buffer`, `content_matches`, `details`, `reason`,
`flow_conditions`; `rule` gồm `sid`, `rev`, `msg`, `rule_ref`, `source_file`,
`line_number`, `raw_text`.

## Tiêu chí PASS

1. Sinh đúng 1 detection; `schema_version = "bt3.detection.v1"`.
2. Đủ mọi trường bắt buộc; SID/rev/msg/classtype/priority lấy đúng từ rule.
3. `matched_info` giải thích được buffer, vị trí content và hướng match.
4. Detection round-trip qua JSON giữ nguyên nội dung.

## Kết quả thực tế

4/4 test OK. Detection thật từ CLI smoke có dạng:

```json
{"schema_version": "bt3.detection.v1", "sid": 4101001, "rev": 1,
 "msg": "BT3 smoke SQLi decoded URI", "flow_id": "...",
 "matched_info": {"orientation": "forward", "buffer": "http_uri", "...": "..."}}
```

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC14.log`
- `TEST/BT3/evidence/jsonl/smoke_detections.jsonl` (3 dòng thật)
- `TEST/BT3/evidence/other/run_cli_smoke.log`

## Ghi chú

- `raw_text` của rule được giữ trong detection để truy vết nguồn.
- Generator không in alert; việc ghi JSONL do pipeline/`JsonlWriter` đảm nhiệm.
