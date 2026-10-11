# T01 — HTTP URL/percent decoding

## 1. Test ID và tên testcase

* **ID:** T01
* **Tên:** HTTP URI/URL percent-encoding decoding
* **Nhóm:** Decoder (Bài tập 2)

## 2. Mục tiêu

Xác minh Decoder giải mã đúng percent-encoding trong HTTP URI/path (ví dụ
`%27%20OR%201%3D1` → `' OR 1=1`) **và** giữ nguyên URI gốc để đối chiếu.
Đồng thời xác minh quy tắc form (`+` = dấu cách) **chỉ** áp dụng cho form/
query, không áp dụng mù quáng cho path.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Percent decoding | `decoder/decoder.py::_decode_percent` (dòng 59) |
| Form decoding | `decoder/decoder.py::_decode_urlencoded` (dòng 120) |
| Ghép block HTTP | `decoder/decoder.py::_decode_http` (dòng 443) |
| Entry point | `decoder/decoder.py::decode_event` (dòng 592) |
| Test method | `tests/test_assignment2_decoder.py::DecoderHttpTestCase::test_uri_percent_decoding` |
| Test bổ trợ | `test_form_plus_becomes_space`, `test_form_semantics_not_applied_to_path`, `test_unit_decode_urlencoded`, `test_malformed_percent_reported_partial` |

## 4. Input và cách tái hiện

Input chính (unit test, tất định):

```python
path = "/search?q=%27%20OR%201%3D1"
```

Fixture end-to-end: `TEST/assignment_2/input_mixed.pcap`, packet HTTP GET
(packet_id = 6).

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderHttpTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. `decoded.http.raw_uri` giữ nguyên `"/search?q=%27%20OR%201%3D1"`.
2. `decoded.http.decoded_uri` = `"/search?q=' OR 1=1"`.
3. `decoded.http.decoded_path` = `"/search"`.
4. `application.path` gốc **không** bị ghi đè.
5. `decode_status == "ok"`.
6. `+` trong path **không** đổi thành dấu cách; form body thì `+` = dấu cách.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T01_decoder_http.log`):

```text
Ran 5 tests in 0.001s
OK
```

Smoke CLI trên `TEST/assignment_2/input_mixed.pcap` (log
`evidence/run_smoke_validate.log`) in ra:

```text
T01 packet_id=6 raw='/search?q=%27%20OR%201%3D1' decoded="/search?q=' OR 1=1"
```

Dòng tương ứng trong `TEST/assignment_2/result_events.jsonl` là **L6**
(packet_id = 6), field `normalized.uri = "/search?q=' OR 1=1"`.

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1, 2, 3, 5 được xác nhận bằng các `assertEqual` trong
  `test_uri_percent_decoding` (cùng với `assertEqual(result["application"]["path"], ...)`
  cho tiêu chí 4).
* Tiêu chí 6 được xác nhận bởi:
  * `test_form_semantics_not_applied_to_path`: `_decode_percent("/a+b/c")` trả về
    `"/a+b/c"` (không đổi `+`).
  * `test_form_plus_becomes_space`: form body `user=nguyen+admin&role=admin%20x`
    → `{"user": "nguyen admin", "role": "admin x"}`.
* Bằng chứng độc lập từ pipeline thật: `evidence/smoke_validate.log` và
  `result_events.jsonl` L6 cho thấy đúng raw/decoded như trên với packet
  HTTP GET thật (Scapy) chứ không chỉ input giả lập.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderHttpTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T01_decoder_http.log`
* JSONL: `TEST/assignment_2/result_events.jsonl` dòng 6;
  `TEST/assignment_2/evidence/smoke_events.jsonl` dòng 6
* Test method: `DecoderHttpTestCase::test_uri_percent_decoding` và 4 test bổ trợ.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* `parse_qsl` cho `query_params` dùng semantics form (`+` = dấu cách) — đúng
  theo chuẩn query string; `decoded_uri`/`decoded_path` thì không áp dụng form.
* Percent-encoding sai định dạng (ví dụ `%zz`) được đánh dấu `partial` với lý do
  `malformed percent-encoding` (test `test_malformed_percent_reported_partial`),
  đây là hành vi có chủ đích và không được coi là PASS của T01 chính.
