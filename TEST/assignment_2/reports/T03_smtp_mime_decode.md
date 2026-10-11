# T03 — SMTP/MIME Base64 và Quoted-Printable decoding

## 1. Test ID và tên testcase

* **ID:** T03
* **Tên:** MIME `Base64` + `Quoted-Printable` transfer decoding
* **Nhóm:** Decoder (Bài tập 2)

## 2. Mục tiêu

Xác minh Decoder chỉ giải mã MIME khi header `Content-Transfer-Encoding` chỉ
định encoding phù hợp (`base64` hoặc `quoted-printable`), trả về body đã giải mã
cùng `status`, và **không** coi mọi body SMTP là MIME.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Tách header/body MIME | `decoder/decoder.py::_split_headers_and_body` |
| Decode Base64/QP | `decoder/decoder.py::_decode_mime` (dòng 317) |
| Lấy raw payload (base64) | `decoder/decoder.py::_raw_payload_bytes` (dòng 191) |
| Entry point | `decoder/decoder.py::decode_event` (dòng 592) |
| Test method | `tests/test_assignment2_decoder.py::DecoderMimeTestCase::test_mime_base64`, `::test_mime_quoted_printable` |
| Test bổ trợ | `test_invalid_base64_reported_error`, `test_no_mime_header_is_not_forced`, `tests/test_assignment2_pipeline.py::ParserIntegrationTestCase::test_smtp_mime_base64_packet` |

## 4. Input và cách tái hiện

Input Base64:

```text
Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8gV29ybGQ=
```

Input Quoted-Printable:

```text
Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=C3=A9 =3D tasty
```

Fixture E2E: `TEST/assignment_2/input_mixed.pcap`, packet SMTP (packet_id = 8
Base64, packet_id = 9 Quoted-Printable).

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest \
  tests.test_assignment2_decoder.DecoderMimeTestCase \
  tests.test_assignment2_pipeline.ParserIntegrationTestCase.test_smtp_mime_base64_packet \
  -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Base64: `decoded.mime.transfer_encoding == "base64"`,
   `decoded_body == "Hello World"`, `status == "ok"`.
2. Quoted-Printable: `transfer_encoding == "quoted-printable"`,
   `decoded_body == "Café = tasty"`, `status == "ok"`.
3. Base64 hỏng (`!!!not-base64!!!`) → `mime.status == "error"`, không crash.
4. Payload không có header `Content-Transfer-Encoding` → `decoded.mime is None`.
5. E2E: packet SMTP Base64 thật qua `parse_packet` cho `decoded_body == "Hello World"`.

## 6. Kết quả thực tế

Unit + E2E test (log `TEST/assignment_2/evidence/run_T03_decoder_mime.log`):

```text
Ran 5 tests in 0.007s
OK
```

Smoke CLI (`evidence/run_smoke_validate.log`):

```text
T03 packet_id=8 base64 body='Hello World' status=ok
T03 packet_id=9 quoted-printable body='Café = tasty' status=ok
```

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: `test_mime_base64` assert `transfer_encoding == "base64"`,
  `decoded_body == "Hello World"`, `mime["status"] == STATUS_OK`.
* Tiêu chí 2: `test_mime_quoted_printable` assert
  `decoded_body == "Café = tasty"` và `status == STATUS_OK`; giá trị này chứng
  minh cả `=C3=A9` (→ `é`) và `=3D` (→ `=`) được xử lý.
* Tiêu chí 3: `test_invalid_base64_reported_error` assert
  `mime["status"] == STATUS_ERROR`.
* Tiêu chí 4: `test_no_mime_header_is_not_forced` với payload `EHLO example.com`
  assert `decoded["mime"] is None`.
* Tiêu chí 5: `test_smtp_mime_base64_packet` chạy Scapy packet thật qua
  `parse_packet` → pipeline và assert `decoded_body == "Hello World"`.
* Bằng chứng pipeline: smoke packet_id=8,9 (hai encoding khác nhau) đều `ok`.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderMimeTestCase tests.test_assignment2_pipeline.ParserIntegrationTestCase.test_smtp_mime_base64_packet -v`
* Log: `TEST/assignment_2/evidence/run_T03_decoder_mime.log`
* JSONL: `TEST/assignment_2/result_events.jsonl` dòng 8 (base64) và dòng 9 (QP)
* Test method: `DecoderMimeTestCase::test_mime_base64`,
  `::test_mime_quoted_printable`, `ParserIntegrationTestCase::test_smtp_mime_base64_packet`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* MIME decode dựa trên raw payload đã lưu dạng base64 (giới hạn
  `max_payload_size`, mặc định 8192 bytes) vì parser Bài tập 1 chỉ trả về dòng
  đầu của SMTP; header/body MIME được tách lại từ raw payload.
* Chỉ hỗ trợ `base64` và `quoted-printable`. Encoding khác (ví dụ `7bit`,
  `8bit`) được coi là không cần decode (`mime is None`).
