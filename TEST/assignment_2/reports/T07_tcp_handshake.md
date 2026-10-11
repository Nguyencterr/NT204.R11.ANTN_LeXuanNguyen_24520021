# T07 — TCP three-way handshake

## 1. Test ID và tên testcase

* **ID:** T07
* **Tên:** TCP three-way handshake (`SYN → SYN/ACK → ACK`)
* **Nhóm:** Flow/Connection Tracker (Bài tập 2)

## 2. Mục tiêu

Tái hiện bắt tay ba bước TCP và xác minh tracker tạo **đúng một flow** với
trạng thái cuối `ESTABLISHED`, đồng thời đếm đúng số packet theo chiều và số
cờ SYN/ACK.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Cập nhật trạng thái TCP | `flow/tracker.py::FlowTracker._update_tcp_state` (dòng 482) |
| Tạo/tra flow | `flow/tracker.py::FlowTracker._get_or_create` (dòng 317) |
| Entry point | `flow/tracker.py::FlowTracker.process` (dòng 204) |
| Test method | `tests/test_assignment2_tracker.py::TrackerHandshakeTestCase::test_handshake_reaches_established` |
| Test bổ trợ | `::test_syn_counts_each_syn_packet` |

## 4. Input và cách tái hiện

Ba event tất định (timestamp tăng dần), cùng 5-tuple:

```text
1. 10.0.0.1:1000 -> 10.0.0.2:80   flags=S   ts=1.0
2. 10.0.0.2:80   -> 10.0.0.1:1000 flags=SA  ts=1.1
3. 10.0.0.1:1000 -> 10.0.0.2:80   flags=A   ts=1.2
```

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerHandshakeTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Sau 3 packet chỉ có **một** flow (không tách thành nhiều flow).
2. Trạng thái cuối `state == "ESTABLISHED"`.
3. `packet_count == 3`, `forward_packet_count == 2`, `backward_packet_count == 1`.
4. `SYN_count == 2` (SYN + SYN/ACK), `ACK_count == 2` (SYN/ACK + ACK).

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T07_tracker_handshake.log`):

```text
Ran 2 tests in 0.000s
OK
```

`test_handshake_reaches_established` assert `state == "ESTABLISHED"`,
`packet_count == 3`, `SYN_count == 2`, `ACK_count == 2`,
`forward_packet_count == 2`, `backward_packet_count == 1`.

Trên fixture E2E (`TEST/assignment_2/result_flows.jsonl` L1), flow
`192.168.1.10:50000 ↔ 192.168.1.20:80` có `SYN_count=2`,
`forward_packet_count=3`, `backward_packet_count=2` và `state=CLOSED`. Lưu ý:
fixture này bao gồm cả bước FIN nên kết thúc `CLOSED` (được kiểm ở T09); T07
kiểm **bắt tay** bằng unit test riêng không có FIN.

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: sau 3 lần `process`, `tracker.flush()` trả về đúng 1 record, và
  mọi packet dùng chung `flow_id` (được tạo một lần ở `_get_or_create`).
* Tiêu chí 2: SYN → `HANDSHAKE`; SYN/ACK đánh dấu `handshake_synack`; ACK cuối
  trong trạng thái `HANDSHAKE` → `ESTABLISHED` (`_update_tcp_state`, nhánh
  `if ack:` và `flow.state == STATE_HANDSHAKE`).
* Tiêu chí 3, 4: các `assertEqual` trong test đối chiếu trực tiếp counters.
* `test_syn_counts_each_syn_packet` assert `SYN_count == 2`, xác nhận cả SYN và
  SYN/ACK đều được tính là SYN.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerHandshakeTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T07_tracker_handshake.log`
* JSONL liên quan: `TEST/assignment_2/result_flows.jsonl` dòng 1
* Test method: `TrackerHandshakeTestCase::test_handshake_reaches_established`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Nếu capture bắt đầu giữa dòng (không thấy SYN), pure ACK vẫn đưa flow sang
  `ESTABLISHED` (mid-stream) — đây là chủ đích, không mô phỏng đầy đủ TCP stack.
* Tracker không kiểm tra tính đúng của `seq/ack`; chỉ dùng flags để suy diễn
  trạng thái.
