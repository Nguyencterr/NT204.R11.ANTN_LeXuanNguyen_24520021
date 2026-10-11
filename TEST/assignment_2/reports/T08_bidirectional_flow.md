# T08 — Bidirectional flow identity and direction

## 1. Test ID và tên testcase

* **ID:** T08
* **Tên:** Bidirectional flow identity (`flow_id`) + direction counters
* **Nhóm:** Flow/Connection Tracker (Bài tập 2)

## 2. Mục tiêu

Xác minh packet A→B và B→A (endpoint đảo chiều) ánh xạ về **cùng một flow**
(`flow_id` ổn định), đồng thời direction và forward/backward counters được
tính chính xác.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Canonical 5-tuple | `flow/tracker.py::_canonical_key` (dòng 73) |
| `flow_id` ổn định (SHA-256) | `flow/tracker.py::_stable_flow_id` (dòng 98) |
| Đếm theo chiều | `flow/tracker.py::FlowTracker._increment_counters` (dòng 359) |
| Xác định chiều | `flow/tracker.py::FlowTracker._update` (dòng 415) |
| Test method | `tests/test_assignment2_tracker.py::TrackerBidirectionalTestCase::test_reversed_endpoints_same_flow` |

## 4. Input và cách tái hiện

Hai event có endpoint đảo chiều, mỗi packet 60 byte:

```text
1. 10.0.0.1:5000 -> 10.0.0.2:443  flags=PA  packet_length=60  ts=1.0
2. 10.0.0.2:443  -> 10.0.0.1:5000 flags=PA  packet_length=60  ts=1.1
```

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerBidirectionalTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Chỉ có **một** flow active sau hai packet.
2. `forward_packet_count == 1`, `backward_packet_count == 1`.
3. `forward_byte_count == 60`, `backward_byte_count == 60`,
   `byte_count == 120`.
4. `flow_id` là SHA-256 digest ổn định (không dùng `hash()` Python).

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T08_tracker_bidirectional.log`):

```text
Ran 1 test in 0.000s
OK
```

Test assert `active_flow_count() == 1` và các counter như trên. Cùng một `flow_id`
được dùng cho cả hai hướng.

Bằng chứng E2E: `TEST/assignment_2/result_flows.jsonl` L2 (HTTP) có
`fwd=1 bwd=1`, L3 (SMTP) `fwd=1 bwd=1`, L4 (UDP DNS) `fwd=1 bwd=1` — mỗi flow
hai chiều chỉ có một record `flow_id`.

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: `_canonical_key` sắp xếp hai endpoint theo thứ tự để
  `(A,B)` và `(B,A)` cho cùng key; `active_flow_count() == 1` xác nhận.
* Tiêu chí 2, 3: `_increment_counters` xác định `forward` bằng
  `(src_ip, src_port) == flow.endpoint_a`, cập nhật đúng counters; test đối chiếu
  trực tiếp.
* Tiêu chí 4: `flow_id = sha256(key|generation)[:32]`; test không cần assert hash
  cụ thể nhưng `flow_id` được kiểm gián tiếp qua việc chỉ có 1 flow, và được
  chứng minh ổn định ở smoke JSONL (mọi packet của cùng flow gộp về một record).

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerBidirectionalTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T08_tracker_bidirectional.log`
* JSONL: `TEST/assignment_2/result_flows.jsonl` dòng 2, 3, 4
* Test method: `TrackerBidirectionalTestCase::test_reversed_endpoints_same_flow`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* `endpoint_a` là endpoint của packet **đầu tiên**; nếu packet đầu tiên là hướng
  ngược lại thì `forward`/`backward` đổi vai trò tương ứng — vẫn nhất quán trong
  nội bộ một flow.
* `flow_id` kết hợp thêm `generation` để cùng 5-tuple tái sử dụng sau timeout
  vẫn có ID mới (xem T12).
