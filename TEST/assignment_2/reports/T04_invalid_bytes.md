# T04 — Invalid bytes / UTF-8 không hợp lệ

## 1. Test ID và tên testcase

* **ID:** T04
* **Tên:** Invalid byte sequences / invalid UTF-8 handling
* **Nhóm:** Decoder (Bài tập 2)

## 2. Mục tiêu

Xác minh payload chứa byte sequence không phải UTF-8 hợp lệ **không** làm crash
pipeline; các byte lỗi được thay thế an toàn và trạng thái/lý do decode được
đánh dấu `partial`/`error` đúng chính sách.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Character decoding | `decoder/decoder.py::_decode_character` (dòng 218) |
| Đọc raw payload | `decoder/decoder.py::_raw_payload_bytes` (dòng 191) |
| Entry point | `decoder/decoder.py::decode_event` (dòng 592) |
| Test method | `tests/test_assignment2_decoder.py::DecoderCharactersTestCase::test_invalid_utf8_partial` |
| Test bổ trợ | `test_valid_utf8_ok`, `test_empty_payload_safe`, `test_size_limit_marks_partial` |

## 4. Input và cách tái hiện

Unit test input (bytes):

```python
raw = b"\xff\xfe\xfd\x31\x32"   # 0xff 0xfe 0xfd không phải UTF-8 hợp lệ
```

Fixture E2E: `TEST/assignment_2/input_mixed.pcap`, packet TCP payload
`b"\xff\xfe\xfd\x01"` (packet_id = 13).

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderCharactersTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Byte hợp lệ UTF-8 → `decoded.text.status == "ok"`, text đúng.
2. Byte không hợp lệ → `decoded.text.status == "partial"` và
   `decode_reason` chứa `"invalid UTF-8"`.
3. `decode_status` tổng hợp của event là `"partial"`.
4. Payload rỗng → không sinh block text, `decode_status == "not_applicable"`,
   không exception.
5. Pipeline tiếp tục xử lý các event sau (không dừng chương trình).

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T04_decoder_chars.log`):

```text
Ran 4 tests in 0.000s
OK
```

Smoke CLI (`evidence/run_smoke_validate.log`):

```text
T04 packet_id=10 text_status=partial decode_status=partial
T04 packet_id=11 text_status=partial decode_status=partial
T04 packet_id=13 text_status=partial decode_status=partial
```

(packet_id 10, 11 là DNS payload nhị phân; packet_id 13 là payload
`\xff\xfe\xfd\x01`.)

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: `test_valid_utf8_ok` với `"xin chào".encode("utf-8")` assert
  `status == STATUS_OK` và text đúng.
* Tiêu chí 2: `test_invalid_utf8_partial` assert
  `decoded["text"]["status"] == STATUS_PARTIAL`, `decode_status == STATUS_PARTIAL`
  và `"invalid UTF-8" in result["decode_reason"]`.
* Tiêu chí 3: cùng test assert `decode_status`.
* Tiêu chí 4: `test_empty_payload_safe` assert `decoded["text"] is None` và
  `decode_status == STATUS_NOT_APPLICABLE`.
* Tiêu chí 5: smoke CLI xử lý packet_id=13 (payload lỗi) rồi vẫn tiếp tục
  packet_id=14, 15 (log `run_smoke_cli.log` ghi "15 written, 0 skipped") — không
  dừng pipeline.
* Bổ sung: `test_size_limit_marks_partial` chứng minh vượt `max_decoded_size`
  cũng được đánh dấu `partial` (giới hạn kích thước).

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderCharactersTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T04_decoder_chars.log`
* JSONL: `TEST/assignment_2/result_events.jsonl` dòng 13;
  `TEST/assignment_2/evidence/smoke_events.jsonl` dòng 13
* Test method: `DecoderCharactersTestCase::test_invalid_utf8_partial`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Chính sách là "replace" (`errors="replace"`): byte lỗi được thay bằng ký tự
  thay thế `�` và đánh dấu `partial`; dữ liệu gốc vẫn còn trong
  `raw_payload_b64`, nên thông tin không bị mất hoàn toàn.
* DNS payload nhị phân bị đánh dấu `partial` khi decode sang text là hành vi
  đúng (không phải lỗi của decoder).
