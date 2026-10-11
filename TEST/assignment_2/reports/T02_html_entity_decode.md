# T02 — HTML entity decoding

## 1. Test ID và tên testcase

* **ID:** T02
* **Tên:** HTML entity decoding
* **Nhóm:** Decoder (Bài tập 2)

## 2. Mục tiêu

Xác minh Decoder giải mã HTML entity trong text HTML (ví dụ `&lt;script&gt;`
→ `<script>`) mà **không** làm biến đổi giá trị raw, và không crash với các
entity khác nhau.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Decode entity | `decoder/decoder.py::_decode_html_entities` (dòng 161) |
| Quyết định có phải HTML | `decoder/decoder.py::_decode_html_block` (dòng 557) |
| Entry point | `decoder/decoder.py::decode_event` (dòng 592) |
| Test method | `tests/test_assignment2_decoder.py::DecoderHtmlTestCase::test_html_entities_decoded` |
| Test bổ trợ | `test_plain_body_not_html`, `test_entity_decode_no_crash` |

## 4. Input và cách tái hiện

Unit test: HTTP response với `Content-Type: text/html` và body:

```text
&lt;script&gt;alert(1)&lt;/script&gt;
```

Fixture E2E: `TEST/assignment_2/input_mixed.pcap`, packet HTTP response
(packet_id = 7) chứa `<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>`.

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderHtmlTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. `decoded.html.decoded_text` = `"<script>alert(1)</script>"`.
2. `decoded.html.changed == True`.
3. `application.body` gốc được giữ nguyên (không bị ghi đè).
4. Body không phải HTML (không chứa entity) không sinh block html, không crash.
5. Các entity như `&amp;`, `&#x27;`, `&apos;` được decode không lỗi.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T02_decoder_html.log`):

```text
Ran 3 tests in 0.000s
OK
```

Smoke CLI (`evidence/run_smoke_validate.log`):

```text
T02 packet_id=7 html_decoded='<html><script>alert(1)</script></html>'
```

Với input `"&lt;script&gt;alert(1)&lt;/script&gt;"` thì assertion kiểm tra đúng
`"<script>alert(1)</script>"` (đã trừ phần `<html>...</html>` bao ngoài của
fixture).

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1, 2: `test_html_entities_decoded` assert
  `decoded_text == "<script>alert(1)</script>"` và `changed is True`.
* Tiêu chí 3: cùng test assert `result["application"]["body"]` vẫn là chuỗi
  entity gốc.
* Tiêu chí 4: `test_plain_body_not_html` assert `decoded["html"] is None` khi
  body là form-urlencoded.
* Tiêu chí 5: `test_entity_decode_no_crash` assert
  `"&amp;&lt;&#x27;&apos;"` → `"&<''"` (hai dấu nháy đơn), chứng minh nhiều loại
  entity được xử lý và không ném exception.
* Bằng chứng pipeline thật: smoke packet_id=7 cho thấy entity được decode trong
  luồng end-to-end.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderHtmlTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T02_decoder_html.log`
* JSONL: `TEST/assignment_2/result_events.jsonl` dòng 7;
  `TEST/assignment_2/evidence/smoke_events.jsonl` dòng 7
* Test method: `DecoderHtmlTestCase::test_html_entities_decoded`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* HTML entity chỉ được decode khi content-type chứa `html` **hoặc** body có dấu
  hiệu entity (`&` kèm `;`). Đây là heuristic có chủ đích để không decode nhầm
  body form (xem `test_plain_body_not_html`).
* Không phân tích DOM/chèn script; chỉ giải mã entity ở mức text.
