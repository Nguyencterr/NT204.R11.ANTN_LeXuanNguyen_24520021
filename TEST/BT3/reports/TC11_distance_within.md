# TC11 — `distance` / `within` tương đối và backtracking

- **Mục:** 4.4 Rule Matching Engine
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_matching.TC11DistanceWithinTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_matching.TC11DistanceWithinTestCase -v
```

- **Kết quả thực tế:** `Ran 5 tests ... OK`, exit 0.

## Mục tiêu

- `distance`/`within` neo vào **cuối match content trước** trong cùng buffer:
  cửa sổ `[prev_end + distance, prev_end + distance + within)`.
- Không được dùng lần xuất hiện tuyệt đối đầu tiên của content thứ hai.
- Khi lần xuất hiện đầu của content trước không dẫn tới chuỗi khớp, phải **backtrack**
  sang lần xuất hiện sau.

## Fixture / input

`TEST/BT3/rules/content_rules.rules`:

| SID | Rule |
| --- | --- |
| 4100505 | `content:"BEGIN"; content:"END"; distance:2; within:3` |
| 4100506 | `content:"BEGIN"; content:"END"; distance:6; within:2` |
| 4100507 | `content:"XY"; content:"ZZ"; distance:1; within:3` |

## Tiêu chí PASS

1. `BEGINxxEND` khớp SID 4100505 tại positions `[0, 7]`.
2. `ENDxxBEGINxxEND` khớp tại `[5, 12]` — `END` ở vị trí 0 **không** được dùng.
3. `BEGINxxxxEND` không khớp SID 4100505 (quá xa).
4. `BEGINxxEND` không khớp SID 4100506 (distance quá lớn).
5. `XYaXYbZZ` khớp SID 4100507 tại `[3, 6]`: lần `XY` đầu ở 0 thất bại nhưng
   backtrack sang `XY` ở 3 mới dẫn tới `ZZ` ở 6.

## Kết quả thực tế

5/5 test OK; positions được assert đúng như bảng trên.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC11.log`

## Ghi chú

- Backtracking có memo hoá trạng thái `(condition_index, previous_end)` và giới hạn bước
  để tránh bùng nổ trên payload lặp.
- Một chuỗi content chỉ được khớp trong **một** buffer; buffer không bị nối với nhau.
