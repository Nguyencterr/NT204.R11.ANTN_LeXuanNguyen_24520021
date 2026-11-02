# TC10 — `offset` / `depth` là cửa sổ tuyệt đối

- **Mục:** 4.4 Rule Matching Engine
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_matching.TC10OffsetDepthTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_matching.TC10OffsetDepthTestCase -v
```

- **Kết quả thực tế:** `Ran 4 tests ... OK`, exit 0.

## Mục tiêu

`offset`/`depth` tạo cửa sổ tuyệt đối `[offset, offset + depth)` trên buffer. Pattern
phải nằm trọn trong cửa sổ; pattern vượt biên hoặc nằm ngoài đều không khớp.

## Fixture / input

`TEST/BT3/rules/content_rules.rules`:

| SID | Rule |
| --- | --- |
| 4100503 | `content:"EVIL"; offset:10; depth:6` |
| 4100504 | `content:"EVIL"; offset:20; depth:6` |
| 4100508 | `content:"EVIL"; offset:10; depth:4` |
| 4100509 | `content:"EVIL"; offset:10; depth:3` |

## Tiêu chí PASS

1. `0123456789EVILtail`: SID 4100503 MATCH, SID 4100504 NO_MATCH.
2. `0123456789EVIL` (pattern kết thúc đúng biên): SID 4100508 MATCH tại position 10,
   window `[10, 14)`; SID 4100509 NO_MATCH vì depth 3 quá ngắn.
3. `0123456789xEVIL`: SID 4100508 NO_MATCH (pattern vượt biên), nhưng SID 4100503 MATCH
   tại position 11 trong cửa sổ rộng hơn.
4. Content nằm ngoài cửa sổ không khớp.

## Kết quả thực tế

4/4 test OK; các position/window được assert chính xác như trên.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC10.log`

## Ghi chú

- `depth` là độ dài cửa sổ, không phải vị trí kết thúc tuyệt đối; điều này được assert
  bằng test biên `[10, 14)`.
- `offset`/`depth` không được trộn với `distance`/`within` trên cùng một `content`
  (parser trả `invalid`).
