# T10 — UDP DNS query/response bidirectional flow

## 1. Test ID và tên testcase

* **ID:** T10
* **Tên:** UDP bidirectional query/response (DNS)
* **Nhóm:** Flow/Connection Tracker (Bài tập 2)

## 2. Mục tiêu

Tái hiện DNS UDP query và response; xác minh tracker nhận diện **một** flow hai
chiều (không tạo handshake kiểu TCP), counters packet/byte chính xác và state
phù hợp cho UDP.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Tạo flow UDP (state `OPEN`) | `flow/tracker.py::FlowTracker._get_or_create` (dòng 317) |
| Ghi nhận endpoint/port | `flow/tracker.py::FlowTracker._extract_endpoints` (dòng 269) |
| Đếm byte/packet | `flow/tracker.py::FlowTracker._packet_bytes` (dòng 391) |
| Test method | `tests/test_assignment2_tracker.py::TrackerUdpTestCase::test_udp_query_response_single_flow` |
| Test E2E | `tests/test_assignment2_pipeline.py::ParserIntegrationTestCase::test_dns_udp_packet`, `::test_dns_response` |

## 4. Input và cách tái hiện

Unit test (mỗi packet 42 byte):

```text
1. 192.168.1.1:53000 -> 8.8.8.8:53  UDP  ts=1.0  payload=b"\x12\x34"
2. 8.8.8.8:53 -> 192.168.1.1:53000  UDP  ts=1.1  payload=b"\x56\x78"
```

Fixture E2E: `TEST/assignment_2/input_mixed.pcap` (packet_id 10 DNS query,
11 DNS response).

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest \
  tests.test_assignment2_tracker.TrackerUdpTestCase \
  tests.test_assignment2_pipeline.ParserIntegrationTestCase.test_dns_udp_packet \
  tests.test_assignment2_pipeline.ParserIntegrationTestCase.test_dns_response -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Sau query + response chỉ có **một** flow UDP.
2. `protocol == "UDP"`, `state == "OPEN"`.
3. `packet_count == 2`, `forward_packet_count == 1`, `backward_packet_count == 1`.
4. `byte_count == 84` (2 × 42).
5. E2E: Scapy DNS query/response qua `parse_packet` cho một flow UDP với
   `application_protocol` cập nhật thành `DNS` (không bị `UNKNOWN` ghi đè).

## 6. Kết quả thực tế

Unit + E2E (log `TEST/assignment_2/evidence/run_T10_tracker_udp.log`):

```text
Ran 3 tests in 0.008s
OK
```

Bằng chứng E2E `TEST/assignment_2/result_flows.jsonl`:
* L4: `OPEN UDP/DNS a=192.168.1.10:53000 b=8.8.8.8:53 pkts=2 fwd=1 bwd=1 bytes=169`
  (byte thật của packet DNS, gồm header UDP/IP).

Smoke (`evidence/run_smoke_validate.log`):

```text
OPEN         UDP  DNS      pkts=2 fwd=1 bwd=1 bytes=169 ...
```

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: endpoint đảo chiều dùng chung canonical key → `active_flow_count() == 1`;
  `flush()` trả về đúng 1 record.
* Tiêu chí 2: `_get_or_create` gán state `OPEN` cho UDP (không có handshake);
  test assert `flow["state"] == "OPEN"`.
* Tiêu chí 3, 4: test assert `packet_count == 2`,
  `forward_packet_count == 1`, `backward_packet_count == 1`, `byte_count == 84`.
* Tiêu chí 5: `test_dns_udp_packet`/`test_dns_response` chạy packet thật và
  `test_dns_udp_packet` assert `application_protocol == "DNS"`; nhánh cập nhật
  application trong `_update` chỉ đặt khi giá trị hiện tại là `UNKNOWN`, nên DNS
  không bị ghi đè.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerUdpTestCase tests.test_assignment2_pipeline.ParserIntegrationTestCase.test_dns_udp_packet tests.test_assignment2_pipeline.ParserIntegrationTestCase.test_dns_response -v`
* Log: `TEST/assignment_2/evidence/run_T10_tracker_udp.log`
* JSONL: `TEST/assignment_2/result_flows.jsonl` dòng 4, 5
* Test method: `TrackerUdpTestCase::test_udp_query_response_single_flow`,
  `ParserIntegrationTestCase::test_dns_udp_packet`, `::test_dns_response`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* UDP state dùng giá trị `OPEN` (tài liệu hóa) thay vì mô phỏng
  `ESTABLISHED`/handshake kiểu TCP.
* Không mô phỏng độ tin cậy/retransmission của UDP.
