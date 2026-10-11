# T13 — Flow statistics (counters, duration, flags)

## 1. Test ID và tên testcase

* **ID:** T13
* **Tên:** Flow statistics — packet/byte counters, direction, duration, TCP flags
* **Nhóm:** Flow/Connection Tracker (Bài tập 2)

## 2. Mục tiêu

Tính toán **độc lập** giá trị kỳ vọng từ packet đầu vào, rồi đối chiếu với
packet/byte counts, forward/backward counts, duration và các counter cờ
SYN/ACK/FIN/RST mà tracker tạo ra.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Đếm packet/byte + chiều | `flow/tracker.py::FlowTracker._increment_counters` (dòng 359) |
| Chọn basis byte | `flow/tracker.py::FlowTracker._packet_bytes` (dòng 391) |
| Serialize record | `flow/tracker.py::Flow.to_record` (dòng 140) |
| Cập nhật `last_seen`/`start_time` | `flow/tracker.py::FlowTracker._update` (dòng 415) |
| Test method | `tests/test_assignment2_tracker.py::TrackerStatsTestCase::test_counters_and_duration` |
| Test bổ trợ | `::test_unknown_does_not_overwrite_known_app`, `::test_payload_fallback_basis` |

## 4. Input và cách tái hiện

Bốn TCP packet cho một flow:

```text
1. 1.1.1.1:1000 -> 2.2.2.2:80  flags=S   packet_length=60  ts=10.0
2. 2.2.2.2:80   -> 1.1.1.1:1000 flags=SA packet_length=60  ts=10.5
3. 1.1.1.1:1000 -> 2.2.2.2:80  flags=A   packet_length=60  ts=11.0
4. 1.1.1.1:1000 -> 2.2.2.2:80  flags=PA  packet_length=74  ts=11.5  application=HTTP
```

Giá trị kỳ vọng tính tay:
* byte_count = 60 + 60 + 60 + 74 = **254**
* forward = packet 1,3,4 → 3 packet, byte = 60 + 60 + 74 = **194**
* backward = packet 2 → 1 packet, byte = **60**
* duration = 11.5 − 10.0 = **1.5**
* SYN = 2, ACK = 3

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerStatsTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. `packet_count == 4`, `byte_count == 254`, `byte_count_basis == "packet"`.
2. `forward_packet_count == 3`, `backward_packet_count == 1`.
3. `forward_byte_count == 194`, `backward_byte_count == 60`.
4. `SYN_count == 2`, `ACK_count == 3`.
5. `duration == 1.5`, `start_time == 10.0`, `last_seen == 11.5`.
6. `application_protocol == "HTTP"`; `UNKNOWN` không ghi đè giá trị đã biết.
7. Fallback: nếu không có `packet_length`, dùng `payload_length` và ghi
   `byte_count_basis == "payload"`.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T13_tracker_stats.log`):

```text
Ran 3 tests in 0.000s
OK
```

Assertions chính (`test_counters_and_duration`) đối chiếu `byte_count`,
`forward_byte_count`, `backward_byte_count`, `SYN_count`, `ACK_count`,
`duration`, `start_time`, `last_seen`, và `byte_count_basis == "packet"` theo
đúng các giá trị tính tay ở mục 4.

E2E `TEST/assignment_2/result_flows.jsonl` L1: `pkts=5 fwd=3 bwd=2 bytes=270
dur=0.4 syn=2 ack=4 fin=2 rst=0` — nhất quán với 5 packet handshake + FIN trong
fixture.

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1, 2, 3: test tính giá trị kỳ vọng bằng biểu thức
  (`60 + 60 + 60 + 74`, `60 + 60 + 74`, `60`) rồi `assertEqual` với record.
* Tiêu chí 4: `_update_tcp_state` tăng counter khi cờ tương ứng có trong
  `flags`; SYN/SA/A/PA cho SYN=2, ACK=3 như test.
* Tiêu chí 5: `_update` cập nhật `last_seen = max(...)`; `to_record` tính
  `duration = last_seen - start_time`; test assert `duration == 1.5`.
* Tiêu chí 6: `test_unknown_does_not_overwrite_known_app` assert flow giữ
  `application_protocol == "HTTP"` dù packet sau là `UNKNOWN`.
* Tiêu chí 7: `test_payload_fallback_basis` bỏ `packet_length`, assert
  `byte_count == 5` và `byte_count_basis == "payload"`.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerStatsTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T13_tracker_stats.log`
* JSONL: `TEST/assignment_2/result_flows.jsonl` dòng 1
* Test method: `TrackerStatsTestCase::test_counters_and_duration`,
  `::test_unknown_does_not_overwrite_known_app`, `::test_payload_fallback_basis`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* `byte_count` dùng **full packet length** (`packet_length`) khi có; nếu không
  có thì fallback `payload_length` và ghi rõ `byte_count_basis` để không trộn
  hai định nghĩa. Trường hợp trộn trong cùng flow → `"mixed"`.
* `duration` là hiệu `last_seen - start_time`; nếu timestamp đi ngược
  (out-of-order) thì lấy giá trị nhỏ nhất cho `start_time` và không để duration âm.
