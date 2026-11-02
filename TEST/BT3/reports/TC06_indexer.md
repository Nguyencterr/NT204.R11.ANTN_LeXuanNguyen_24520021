# TC06 — Repository / Indexer không làm mất rule có thể khớp

- **Mục:** 4.3 Rule Repository / Indexer
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_repository.TC06IndexerTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_repository.TC06IndexerTestCase -v
```

- **Kết quả thực tế:** `Ran 5 tests ... OK`, exit 0.

## Mục tiêu

Index theo protocol + port phải trả về **superset** của các rule có thể khớp, giữ thứ tự
ổn định, và xử lý đúng range mở/range kín/port đơn/`any` cùng chiều `<>`.

## Fixture / input

| Thành phần | Đường dẫn |
| --- | --- |
| Rules | `TEST/BT3/rules/header_rules.rules` |
| Truy vấn mẫu | `TEST/BT3/evidence/jsonl/candidate_selection.jsonl` |

## Tiêu chí PASS

1. Event TCP `12345 → 80` trả các rule `any/any`, port đơn, range high.
2. Range mở `:1024` không bị mất khi event dùng port thấp.
3. Event UDP DNS trả rule UDP `any → 53` và rule `<>` CIDR.
4. Event đảo chỉ trả rule `<>` có thể khớp chiều đảo.
5. Protocol ngoài TCP/UDP trả 0 candidate kèm lý do.
6. Thứ tự candidate ổn định sau `rebuild_index()`.
7. `pool_size`, `port_candidate_count`, `candidate_count` được báo cáo nhất quán.

## Kết quả thực tế

Từ `candidate_selection.jsonl`:

| Truy vấn | candidate_count | pool_size | SID |
| --- | --: | --: | --- |
| TCP forward any/any | 3 | 5 | 4100101, 4100103, 4100107 |
| TCP reverse cho `<>` CIDR | 1 | 5 | 4100101 |
| UDP DNS | 2 | 2 | 4100104, 4100105 |
| Protocol ICMP | 0 | 0 | — (reason: not TCP/UDP) |

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC06.log`
- `TEST/BT3/evidence/jsonl/candidate_selection.jsonl`

## Ghi chú

- Index chỉ dùng điều kiện **cần** (protocol/port) rồi lọc lại bằng `match_rule_header`
  dùng chung với matcher. Vì vậy không có nguy cơ index bỏ sót rule mà matcher sẽ khớp.
- Port của event thiếu (`None`) không khớp rule port đơn, đúng ngữ nghĩa “không đủ dữ kiện”.
