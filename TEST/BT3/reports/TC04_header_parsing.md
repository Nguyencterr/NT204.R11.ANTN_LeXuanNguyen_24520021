# TC04 — Parse header: any / IPv4 / CIDR / port / range / hướng

- **Mục:** 4.2 Rule Parser & Validator
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_parser.TC04HeaderParsingTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_parser.TC04HeaderParsingTestCase -v
```

- **Kết quả thực tế:** `Ran 7 tests ... OK`, exit 0.

## Mục tiêu

Chuẩn hoá và validate đầy đủ header được phép:

- action `alert`, protocol `tcp`/`udp`;
- địa chỉ `any`, IPv4 đơn, IPv4 CIDR;
- port `any`, port đơn, range kín `1000:2000`, range mở `:1024`, `1024:`;
- hướng `->` và `<>`;
- từ chối IP/port/hướng sai thành `invalid`.

## Fixture / input

| File | Vai trò |
| --- | --- |
| `TEST/BT3/rules/header_rules.rules` | 7 rule hợp lệ cho các dạng selector |
| `TEST/BT3/rules/header_invalid.rules` | 4 rule sai + 1 rule hợp lệ cuối |

## Tiêu chí PASS

1. Cả 7 rule trong `header_rules.rules` đều `valid`.
2. `any` được biểu diễn bằng selector `kind = any`, không phải chuỗi rỗng.
3. CIDR `192.168.1.0/24` giữ network đã chuẩn hoá.
4. `:1024` → `(0, 1024)`, `1024:` → `(1024, 65535)`.
5. IPv4 đơn và port đơn giữ đúng giá trị.
6. 4 rule sai nhận `invalid` với lý do: IP sai, port ngoài 0..65535, range đảo,
   direction sai; rule cuối vẫn `valid` (SID `4100114`).

## Kết quả thực tế

- `header_rules.rules`: 7/7 `valid`.
- `header_invalid.rules`: `[invalid, invalid, invalid, invalid, valid]`.
- Thông điệp thực tế:
  - `invalid source address '192.168.1.300'`
  - `source port 70000 is outside 0..65535`
  - `invalid source port range '2000:1000': start is greater than end`
  - `direction must be '->' or '<>', got '<-'`

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC04.log`
- `TEST/BT3/evidence/jsonl/parse_results_all_rules.jsonl`
- `TEST/BT3/evidence/jsonl/candidate_selection.jsonl`

## Ghi chú

- IPv6 và địa chỉ/port phủ định (`!`) được phân loại `unsupported`, không bị coi là
  IPv4 hợp lệ.
- Range mở được chuẩn hoá ngay ở parser nên indexer không phải xử lý trường hợp đặc biệt.
