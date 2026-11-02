# TC02 — Malformed rule bị đánh dấu invalid, rule sau vẫn parse

- **Mục:** 4.2 Rule Parser & Validator
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_parser.TC02InvalidRuleTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_parser.TC02InvalidRuleTestCase -v
```

- **Kết quả thực tế:** `Ran 2 tests ... OK`, exit 0.

## Mục tiêu

Một rule sai cú pháp phải nhận `status = "invalid"`, có `reason`/`diagnostic`, và
**không** làm dừng việc parse các rule phía sau.

## Fixture / input

`TEST/BT3/rules/invalid_rules.rules` gồm 4 dòng:

1. `sid:` thiếu giá trị.
2. Chuỗi quote không đóng.
3. Header direction hỏng (`- >`).
4. Rule hợp lệ sau các rule lỗi.

Ngoài ra test còn parse trực tiếp các chuỗi rác: rỗng, thiếu `(`, thiếu `sid`,
option không có `name:value`.

## Tiêu chí PASS

1. 3 rule đầu có `status = invalid`, `rule = None`, `reason` không rỗng và
   diagnostic `SYNTAX_ERROR`.
2. Rule thứ 4 vẫn `valid`, SID `4100204`, `content = "ok"`.
3. `rule_ref` giữ đúng `invalid_rules.rules:2..5`.
4. Parser không ném exception với bất kỳ chuỗi rác nào; mọi kết quả đều `invalid`
   và có `reason`.

## Kết quả thực tế

- `invalid_rules.rules`: `[invalid, invalid, invalid, valid]`.
- Rule hợp lệ cuối: SID `4100204`, msg `"TC02 valid after invalid"`,
  content `"ok"`.
- 5 chuỗi rác đều trả `invalid` kèm lý do; không có exception thoát ra ngoài.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC02.log`
- `TEST/BT3/evidence/jsonl/parse_results_all_rules.jsonl` (các dòng
  `invalid_rules.rules:2..4`).

## Ghi chú

- Lỗi được cô lập theo từng candidate; parser dùng `try/except` bao quanh mỗi rule.
- `rev` thiếu sẽ mặc định `1`; đây là lựa chọn được tài liệu hoá, không phải lỗi.
