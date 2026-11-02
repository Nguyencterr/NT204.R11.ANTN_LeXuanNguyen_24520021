# TC09 — `content` phân biệt hoa/thường và `nocase`

- **Mục:** 4.4 Rule Matching Engine
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_matching.TC09ContentNocaseTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_matching.TC09ContentNocaseTestCase -v
```

- **Kết quả thực tế:** `Ran 3 tests ... OK`, exit 0.

## Mục tiêu

- Mặc định `content` phân biệt hoa/thường.
- `nocase` chỉ gập ASCII, giữ nguyên vị trí byte trên payload UTF-8.
- Rule không có `nocase` không được khớp khi chỉ khác case.

## Fixture / input

`TEST/BT3/rules/content_rules.rules`:

| SID | Content | Modifier |
| --- | --- | --- |
| 4100501 | `Admin` | không |
| 4100502 | `Admin` | `nocase` |

## Tiêu chí PASS

1. Payload chứa đúng `Admin` khớp cả hai rule.
2. Payload chỉ có `admin` khớp rule `nocase`, không khớp rule phân biệt hoa/thường.
3. Payload chỉ có `ADMIN` cũng chỉ khớp rule `nocase`.
4. Vị trí match được báo cáo chính xác.

## Kết quả thực tế

- `Admin`: SID 4100501 + 4100502 MATCH.
- `admin`: chỉ SID 4100502 MATCH.
- `ADMIN`: chỉ SID 4100502 MATCH.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC09.log`

## Ghi chú

- `nocase` dùng `bytes.lower()` trên ASCII để không làm lệch offset của UTF-8; đây là
  lựa chọn được tài liệu hoá, không dùng Unicode case-fold đầy đủ.
