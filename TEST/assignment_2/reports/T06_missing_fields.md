# T06 — Missing optional fields

## 1. Test ID và tên testcase

* **ID:** T06
* **Tên:** Missing optional fields representation (`null`/`[]`)
* **Nhóm:** Preprocessor (Bài tập 2)

## 2. Mục tiêu

Xác minh field tùy chọn bị thiếu được biểu diễn nhất quán bằng `null` hoặc `[]`
theo schema, **không** phát sinh exception, và event vẫn được gắn metadata
(`preprocess_status`, `processing_action`, `reason`) phù hợp.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Coerce block + default optional | `preprocessor/preprocessor.py::preprocess_event` (dòng 144, đoạn `setdefault`) |
| Cổng/port | `preprocessor/preprocessor.py::_coerce_port` (dòng 49) |
| Timestamp | `preprocessor/preprocessor.py::_coerce_float` (dòng 33) |
| Test method | `tests/test_assignment2_preprocessor.py::PreprocessorMissingFieldsTestCase::test_missing_optional_fields_no_crash` |
| Test bổ trợ | `test_missing_required_field_invalid` |

## 4. Input và cách tái hiện

Unit test input — chỉ có field bắt buộc, thiếu hầu hết phần còn lại:

```python
{
    "packet_id": 1,
    "timestamp": 100.0,
    "src_ip": "1.1.1.1",
    "dst_ip": "2.2.2.2",
    "transport": {"protocol": "UDP"},
}
```

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_preprocessor.PreprocessorMissingFieldsTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Không ném exception.
2. `application` mặc định `{"protocol": "UNKNOWN"}`.
3. `errors == []`, `raw_payload_b64 is None`, `packet_length is None`,
   `payload_length == 0`.
4. `src_port is None`, `dst_port is None` khi transport không có port.
5. `normalized.http_headers is None` cho event không phải HTTP.
6. Field bắt buộc thiếu (`src_ip = None`) → `preprocess_status == "invalid"` với
   lý do `"missing src_ip"`.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T06_preprocessor_missing.log`):

```text
Ran 2 tests in 0.000s
OK
```

`test_missing_optional_fields_no_crash` trả về `preprocess_status == "partial"`
(không phải exception) với các giá trị `null`/`[]`/`0` như trên.

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1–5: các `assertEqual`/`assertIsNone` trong
  `test_missing_optional_fields_no_crash` kiểm tra trực tiếp từng giá trị
  (`application`, `errors`, `raw_payload_b64`, `packet_length`, `payload_length`,
  `src_port`, `dst_port`, `normalized.http_headers`).
* Tiêu chí 6: `test_missing_required_field_invalid` assert `src_ip=None` →
  `STATUS_INVALID` và `"missing src_ip"` trong `preprocess_reason`.
* Không có exception nào bị ném ra — test pass nghĩa là luồng chạy trọn vẹn.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_preprocessor.PreprocessorMissingFieldsTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T06_preprocessor_missing.log`
* Test method: `PreprocessorMissingFieldsTestCase::test_missing_optional_fields_no_crash`,
  `::test_missing_required_field_invalid`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Event chỉ thiếu optional (ví dụ `application`, `packet_length`) được đánh dấu
  `partial`, không phải `invalid`: đây là chủ đích để event vẫn đi tiếp vào
  tracker khi có đủ 5-tuple.
* `src_ip`/`dst_ip` được coi là bắt buộc cho flow tracking, nên thiếu chúng là
  `invalid`.
