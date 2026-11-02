# TC13 — Một event khớp nhiều rule ⇒ nhiều Detection Event độc lập

- **Mục:** 4.5 Rule Evaluation Engine
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_evaluation.TC13MultipleMatchesTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_evaluation.TC13MultipleMatchesTestCase -v
```

- **Kết quả thực tế:** `Ran 2 tests ... OK`, exit 0.

## Mục tiêu

Evaluation không được dừng ở match đầu tiên. Mọi rule khớp phải sinh một Detection Event
riêng, giữ đủ SID/rule metadata, và toàn bộ phải JSON-serializable.

## Fixture / input

`TEST/BT3/rules/multi_match.rules`:

| SID | Content |
| --- | --- |
| 4100801 | `GET` |
| 4100802 | `/index` |
| 4100803 | `/missing` |

Event HTTP tổng hợp chứa cả `GET` và `/index`.

## Tiêu chí PASS

1. Event khớp đúng 2 rule (`4100801`, `4100802`), không khớp `4100803`.
2. Sinh đúng 2 Detection Event, mỗi detection một SID.
3. `statistics.matches = 2`, `detections_generated = 2`, `no_match_count = 1`.
4. Mỗi detection serialize/deserialize JSON không mất dữ liệu.

## Kết quả thực tế

- 2 detection độc lập cho SID `4100801` và `4100802`.
- Rule `4100803` được đếm `no_match`, không sinh detection.
- Toàn bộ detection round-trip qua `json.dumps`/`json.loads` thành công.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC13.log`
- `TEST/BT3/evidence/jsonl/smoke_detections.jsonl` (minh hoạ nhiều detection từ PCAP thật)

## Ghi chú

- Thứ tự detection theo thứ tự candidate ổn định trong repository.
- Lỗi ở một candidate được cô lập; candidate khác vẫn được đánh giá
  (xem `run_contract_evaluation.log`).
