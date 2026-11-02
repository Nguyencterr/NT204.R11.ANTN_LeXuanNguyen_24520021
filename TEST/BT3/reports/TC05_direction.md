# TC05 — `->` một chiều, `<>` hai chiều nhưng vẫn ghi hướng

- **Mục:** 4.4 Rule Matching Engine
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_matching.TC05DirectionTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_matching.TC05DirectionTestCase -v
```

- **Kết quả thực tế:** `Ran 2 tests ... OK`, exit 0.

## Mục tiêu

Header `->` chỉ được khớp theo chiều thuận. Header `<>` được khớp cả hai chiều,
nhưng kết quả phải ghi rõ `orientation = "forward"` hoặc `"reverse"`.

## Fixture / input

`TEST/BT3/rules/direction_rules.rules`:

| SID | Header | Nội dung |
| --- | --- | --- |
| 4100401 | `alert tcp 192.168.1.10 any -> 192.168.1.20 8080` | `GET` |
| 4100402 | `alert tcp 192.168.1.10 any <> 192.168.1.20 8080` | `GET` |

## Tiêu chí PASS

1. Event thuận `192.168.1.10 → 192.168.1.20:8080` khớp **cả hai** rule.
2. Rule `->` báo `orientation = "forward"`.
3. Event đảo `192.168.1.20:8080 → 192.168.1.10` **chỉ** khớp rule `<>`.
4. Rule `<>` ở chiều đảo báo `orientation = "reverse"`.

## Kết quả thực tế

- Event thuận: cả 2 SID `4100401/4100402` MATCH; SID 4100401 có orientation forward.
- Event đảo: chỉ SID `4100402` MATCH với orientation `reverse`; SID `4100401` NO_MATCH.
- Không có trường hợp `->` khớp chiều đảo.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC05.log`
- `TEST/BT3/evidence/jsonl/candidate_selection.jsonl` (truy vấn thuận/đảo)

## Ghi chú

- Indexer chỉ xét orientation đảo cho rule `<>`; header matcher dùng chung logic này nên
  candidate và kết quả cuối không thể lệch nhau.
