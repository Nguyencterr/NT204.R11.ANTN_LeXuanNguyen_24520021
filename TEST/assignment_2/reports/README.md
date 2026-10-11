# Báo cáo kiểm thử Bài tập 2 — Decoder, Preprocessor & Flow/Connection Tracker

Thư mục này chứa báo cáo riêng cho từng testcase **T01–T14** của Bài tập 2,
kèm bằng chứng có thể kiểm tra lại (log test, output JSONL, fixture PCAP).

## 1. Mục đích

* Mỗi testcase có **một report độc lập** giải thích: mục tiêu, code liên quan,
  input/tái hiện, tiêu chí PASS, kết quả thực tế, lý do hoàn thành và bằng chứng.
* Bằng chứng được lưu thô (raw), không chỉnh sửa tay:
  * `TEST/assignment_2/evidence/` — log chạy test từng testcase, log smoke,
    output JSONL.
  * `TEST/assignment_2/` — fixture và kết quả tái hiện.

## 2. Bảng tổng hợp T01–T14

| ID | Testcase | Trạng thái | Test method chính | Report | Bằng chứng |
| --: | --- | :--: | --- | --- | --- |
| T01 | HTTP URL/percent decoding | PASS | `DecoderHttpTestCase::test_uri_percent_decoding` | [T01](T01_url_percent_decode.md) | `evidence/run_T01_decoder_http.log` |
| T02 | HTML entity decoding | PASS | `DecoderHtmlTestCase::test_html_entities_decoded` | [T02](T02_html_entity_decode.md) | `evidence/run_T02_decoder_html.log` |
| T03 | SMTP/MIME Base64 + QP | PASS | `DecoderMimeTestCase::test_mime_base64`, `::test_mime_quoted_printable` | [T03](T03_smtp_mime_decode.md) | `evidence/run_T03_decoder_mime.log` |
| T04 | Invalid bytes / UTF-8 | PASS | `DecoderCharactersTestCase::test_invalid_utf8_partial` | [T04](T04_invalid_bytes.md) | `evidence/run_T04_decoder_chars.log` |
| T05 | Normalization | PASS | `PreprocessorNormalizationTestCase::test_protocol_and_header_normalization` | [T05](T05_normalization.md) | `evidence/run_T05_preprocessor_norm.log` |
| T06 | Missing optional fields | PASS | `PreprocessorMissingFieldsTestCase::test_missing_optional_fields_no_crash` | [T06](T06_missing_fields.md) | `evidence/run_T06_preprocessor_missing.log` |
| T07 | TCP handshake | PASS | `TrackerHandshakeTestCase::test_handshake_reaches_established` | [T07](T07_tcp_handshake.md) | `evidence/run_T07_tracker_handshake.log` |
| T08 | Bidirectional flow | PASS | `TrackerBidirectionalTestCase::test_reversed_endpoints_same_flow` | [T08](T08_bidirectional_flow.md) | `evidence/run_T08_tracker_bidirectional.log` |
| T09 | TCP FIN/RST close | PASS | `TrackerCloseTestCase::test_fin_both_directions_closes_immediately` | [T09](T09_tcp_close_reset.md) | `evidence/run_T09_tracker_close.log` |
| T10 | UDP DNS query/response | PASS | `TrackerUdpTestCase::test_udp_query_response_single_flow` | [T10](T10_udp_dns_query_response.md) | `evidence/run_T10_tracker_udp.log` |
| T11 | Concurrent flows | PASS | `TrackerConcurrentTestCase::test_distinct_5_tuples_distinct_flows` | [T11](T11_concurrent_flows.md) | `evidence/run_T11_tracker_concurrent.log` |
| T12 | Idle timeout | PASS | `TrackerTimeoutTestCase::test_tcp_idle_timeout` | [T12](T12_idle_timeout.md) | `evidence/run_T12_tracker_timeout.log` |
| T13 | Flow statistics | PASS | `TrackerStatsTestCase::test_counters_and_duration` | [T13](T13_flow_statistics.md) | `evidence/run_T13_tracker_stats.log` |
| T14 | Malformed event | PASS | `TrackerMalformedTestCase::test_invalid_event_then_valid_event` | [T14](T14_malformed_event.md) | `evidence/run_T14_pipeline_malformed.log` |

**Tổng:** PASS = 14, FAIL = 0, BLOCKED/NOT VERIFIED = 0.

## 3. Lệnh chạy

Repo dùng `unittest` và virtualenv `.venv` (Python 3.14, Scapy 2.7.0).

Chạy toàn bộ suite:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Chạy riêng từng testcase (ví dụ T01, T07, T12):

```bash
.venv/bin/python -m unittest tests.test_assignment2_decoder.DecoderHttpTestCase -v
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerHandshakeTestCase -v
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerTimeoutTestCase -v
```

Kết quả toàn bộ suite gần nhất: **Ran 54 tests — OK**
(log `evidence/run_full_suite.log`). Phân bổ:
decoder 16, preprocessor 14, tracker 15, pipeline 9.

## 4. Tái tạo output JSONL (smoke test)

```bash
.venv/bin/python main.py \
  --pcap TEST/assignment_2/input_mixed.pcap \
  --output TEST/assignment_2/evidence/smoke_events.jsonl \
  --flows-output TEST/assignment_2/evidence/smoke_flows.jsonl \
  --tcp-idle-timeout 5 --udp-idle-timeout 3

.venv/bin/python tests/validate_assignment2_smoke.py \
  TEST/assignment_2/evidence/smoke_events.jsonl \
  TEST/assignment_2/evidence/smoke_flows.jsonl
```

`validate_assignment2_smoke.py` parse từng dòng JSONL (báo lỗi nếu có dòng hỏng)
và in tóm tắt flow + các giá trị decode tiêu biểu. Kết quả:
events 15 dòng, flows 7 dòng, tất cả parse OK
(log `evidence/run_smoke_validate.log`).

## 5. Bằng chứng dùng chung

* `evidence/run_full_suite.log` — log toàn bộ suite (54 tests, OK).
* `evidence/run_smoke_cli.log` — log CLI smoke test.
* `evidence/run_smoke_validate.log` — kết quả validate JSONL.
* `evidence/smoke_events.jsonl`, `evidence/smoke_flows.jsonl` — output thô.
* `TEST/assignment_2/input_mixed.pcap` — fixture PCAP.
* `TEST/assignment_2/result_events.jsonl`, `result_flows.jsonl` — fixture output
  được tạo bởi `tests/generate_assignment2_fixtures.py`.

## 6. Hạn chế còn lại

* Không giải mã TLS/HTTPS (chỉ HTTP/1.x plaintext).
* MIME chỉ decode khi có header `Content-Transfer-Encoding` phù hợp.
* DNS binary text bị đánh dấu `partial` khi decode sang text (hành vi đúng).
* Raw payload chỉ giữ prefix giới hạn (`max_payload_size`, mặc định 8192 byte),
  mã hoá base64 để tương thích JSONL.
* Flow tracker chưa hỗ trợ IP fragmentation reassembly.
* Số test thay đổi 53 → 54 do bổ sung test T05
  (`test_timestamp_and_uri_normalization`) trong quá trình làm report; các report
  phản ánh số liệu mới nhất đã chạy thực tế.
