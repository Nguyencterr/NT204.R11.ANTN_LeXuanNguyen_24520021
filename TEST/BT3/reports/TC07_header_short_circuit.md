# TC07 — Header mismatch short-circuit trước khi match content

- **Mục:** 4.4 Rule Matching Engine
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_matching.TC07HeaderShortCircuitTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_matching.TC07HeaderShortCircuitTestCase -v
```

- **Kết quả thực tế:** `Ran 1 test ... OK`, exit 0.

## Mục tiêu

Chứng minh thứ tự đánh giá: header được kiểm tra **trước** content; nếu header sai thì
content matcher không được gọi (không tốn CPU, không thể sinh false positive).

## Cách kiểm tra

Test thay `engine.content_matcher` bằng một hàm luôn ném `AssertionError("spy called")`.
Sau đó match một event có header sai (protocol/port không khớp).

## Tiêu chí PASS

1. Kết quả là `NO_MATCH` với lý do header.
2. Spy content matcher **không** được gọi (không có exception lan ra).
3. Với event có header khớp, spy được gọi — chứng minh phép thử có hiệu lực.

## Kết quả thực tế

- Event header sai: `NO_MATCH`, reason chứa `header mismatch`; spy không được gọi.
- Event header đúng: spy được gọi (test kiểm soát dương tính).

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC07.log`

## Ghi chú

- Đây là kiểm tra trực tiếp bằng “spy”, không chỉ suy luận từ kết quả match, nên chứng minh
  được short-circuit thực sự xảy ra.
