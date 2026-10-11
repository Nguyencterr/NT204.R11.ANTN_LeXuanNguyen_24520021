# T05 — Normalization

## 1. Test ID và tên testcase

* **ID:** T05
* **Tên:** Protocol / IP-domain / HTTP header / URI / timestamp normalization
* **Nhóm:** Preprocessor (Bài tập 2)

## 2. Mục tiêu

Xác minh Preprocessor chuẩn hóa nhất quán: tên protocol, IP/domain, HTTP header
name (lowercase), Host (lowercase), URI (dùng giá trị đã decode) và timestamp
(float) — đồng thời **không** phá giá trị raw.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Chuẩn hóa IP | `preprocessor/preprocessor.py::_normalize_ip` (dòng 80) |
| Chuẩn hóa header/Host | `preprocessor/preprocessor.py::_normalize_headers` (dòng 104) |
| Protocol ứng dụng | `preprocessor/preprocessor.py::_application_protocol` (dòng 133) |
| Entry point | `preprocessor/preprocessor.py::preprocess_event` (dòng 144) |
| Test method | `tests/test_assignment2_preprocessor.py::PreprocessorNormalizationTestCase::test_protocol_and_header_normalization` |
| Test bổ trợ | `test_ip_normalization`, `test_leading_zero_ipv4_invalid`, `test_bad_ip_invalid`, `test_unsupported_protocol_partial`, `test_timestamp_and_uri_normalization` |

## 4. Input và cách tái hiện

Unit test input tiêu biểu:

```python
src_ip = " 192.168.1.10 "
dst_ip = "2001:0DB8:0000:0000:0000:0000:0000:0001"
headers = {"Host": "EXAMPLE.com", "Content-Type": "text/html"}
application = {"protocol": "http", "path": "/search?q=%27%20OR%201%3D1"}
```

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_preprocessor.PreprocessorNormalizationTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. `transport_protocol == "TCP"`, `application_protocol == "HTTP"` (chuẩn hóa
   uppercase từ `"http"`).
2. IP canonical: `src_ip " 192.168.1.10 "` → `"192.168.1.10"`;
   IPv6 → `"2001:db8::1"`.
3. Header name lowercase trong `normalized.http_headers`; Host lowercase.
4. `normalized.uri` dùng giá trị đã decode; timestamp là `float`.
5. Giá trị raw (`application.headers["Host"]`, `decoded.http.raw_uri`) không bị
   ghi đè.
6. IP sai định dạng hoặc IPv4 có leading zero → `invalid` với lý do rõ ràng.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T05_preprocessor_norm.log`):

```text
Ran 6 tests in 0.001s
OK
```

Bao gồm test mới bổ sung `test_timestamp_and_uri_normalization` (assert
`normalized["timestamp"] == 100.0` kiểu float, `normalized["uri"] ==
"/search?q=' OR 1=1"`, `normalized["host"] == "example.com"`, và
`decoded.http.raw_uri` giữ nguyên).

Smoke CLI `result_events.jsonl` L6 cho thấy `normalized.uri =
"/search?q=' OR 1=1"` và `normalized.http_headers.host = "example.com"`.

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: `test_protocol_and_header_normalization` assert
  `transport_protocol == "TCP"`, `application_protocol == "HTTP"` từ input
  `protocol: "http"`.
* Tiêu chí 2: `test_ip_normalization` assert `" 192.168.1.10 "` → `"192.168.1.10"`
  và IPv6 → `"2001:db8::1"`.
* Tiêu chí 3: cùng test assert `normalized["http_headers"]["host"] == "example.com"`
  và `normalized["host"] == "example.com"`; đồng thời raw
  `application["headers"]["Host"] == "EXAMPLE.com"` vẫn nguyên (tiêu chí 5).
* Tiêu chí 4: `test_timestamp_and_uri_normalization` (bổ sung trong lần này) assert
  timestamp float và URI đã decode.
* Tiêu chí 6: `test_bad_ip_invalid` và `test_leading_zero_ipv4_invalid` assert
  `preprocess_status == "invalid"` kèm lý do.
* Phiên bản trước T05 có 5 test; đã bổ sung `test_timestamp_and_uri_normalization`
  để bịt khoảng trống assertion cho URI/timestamp.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_preprocessor.PreprocessorNormalizationTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T05_preprocessor_norm.log`
* JSONL: `TEST/assignment_2/result_events.jsonl` dòng 6 (block `normalized`)
* Test method: `PreprocessorNormalizationTestCase::test_protocol_and_header_normalization`,
  `::test_ip_normalization`, `::test_timestamp_and_uri_normalization`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Chỉ chuẩn hóa **key** của HTTP header thành lowercase; **value** được giữ
  nguyên, riêng Host được lowercase (domain không phân biệt hoa/thường).
* IPv4 có leading zero (`192.168.001.010`) bị coi là **invalid** — theo thư viện
  chuẩn `ipaddress` của Python; hành vi này được test và ghi nhận rõ.
