# TC03 — Keyword ngoài phạm vi bị đánh dấu unsupported

- **Mục:** 4.2 Rule Parser & Validator
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_parser.TC03UnsupportedKeywordTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_parser.TC03UnsupportedKeywordTestCase -v
```

- **Kết quả thực tế:** `Ran 2 tests ... OK`, exit 0.

## Mục tiêu

Các keyword/protocol hợp lệ của Snort nhưng ngoài subset Bài 3 phải được phân loại
`unsupported` (không phải `invalid`), giữ diagnostic, và **không** được đưa vào
repository để so khớp.

## Fixture / input

`TEST/BT3/rules/unsupported_rules.rules`:

| Dòng | Nội dung ngoài phạm vi |
| --- | --- |
| 2 | `pcre:"/foo/i"` |
| 3 | `byte_test:1,>,2,0` |
| 4 | protocol `icmp` |
| 5 | rule hợp lệ có `content:"ok"` |

## Tiêu chí PASS

1. 3 rule đầu `status = unsupported`; lý do nêu đúng `pcre`, `byte_test`, `icmp`.
2. Rule thứ 4 vẫn `valid` (SID `4100304`).
3. Repository chỉ chứa 1 rule hợp lệ; diagnostic của 3 rule unsupported vẫn được giữ.

## Kết quả thực tế

- Parse: `[unsupported, unsupported, unsupported, valid]`.
- Repository: `len = 1`, SID hợp lệ duy nhất `4100304`.
- Diagnostics: 3 mục `UNSUPPORTED_RULE` tương ứng.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC03.log`
- `TEST/BT3/evidence/jsonl/parse_results_all_rules.jsonl`
- `TEST/BT3/evidence/jsonl/repository_diagnostics.jsonl`

## Ghi chú

- Token bare không có `name:value` và không nằm trong danh sách keyword no-value đã biết
  được coi là **invalid** (lỗi cú pháp), không phải unsupported.
- `pcre`, `byte_test` có giá trị nên được nhận diện là keyword ngoài phạm vi.
