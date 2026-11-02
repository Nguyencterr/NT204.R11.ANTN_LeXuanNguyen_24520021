# TC12 — TCP `flags` và `dsize` theo payload length

- **Mục:** 4.4 Rule Matching Engine
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_matching.TC12FlagsDsizeTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_matching.TC12FlagsDsizeTestCase -v
```

- **Kết quả thực tế:** `Ran 4 tests ... OK`, exit 0.

## Mục tiêu

- `flags:` yêu cầu **mọi** cờ khai báo đều có mặt; cờ thừa không cản trở.
- Thiếu trường flags ⇒ NO_MATCH, không crash.
- `dsize` so sánh với **payload length**, tuyệt đối không dùng packet/frame length
  hay byte counter của flow.

## Fixture / input

`TEST/BT3/rules/flags_dsize.rules`:

| SID | Điều kiện |
| --- | --- |
| 4100601 | `flags:S` |
| 4100602 | `flags:SA` |
| 4100603 | `dsize:>4` |
| 4100604 | `dsize:4` |
| 4100605 | `dsize:<=4` |

## Tiêu chí PASS

1. Event `S`: khớp 4100601, không khớp 4100602.
2. Event `SA`: khớp cả 4100601 và 4100602.
3. Event `A`: không khớp 4100601.
4. Event không có flags: NO_MATCH với lý do “no TCP flags”.
5. Payload 5 byte, `packet_length=1500`: 4100603 MATCH, 4100604/4100605 NO_MATCH;
   `details.dsize.payload_length = 5` chứng minh không dùng 1500.
6. Payload đúng 4 byte: 4100604 và 4100605 MATCH, 4100603 NO_MATCH.

## Kết quả thực tế

4/4 test OK, đúng toàn bộ biên `dsize` và ngữ nghĩa flags ở trên.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC12.log`

## Ghi chú

- `dsize` hỗ trợ `>`, `<`, `=`, `>=`, `<=`; dạng range/`!=` bị parser phân loại
  `unsupported`, giá trị không phải số bị `invalid`.
- UDP + `flags` bị từ chối ở parser (`invalid`).
