# T12 — Idle timeout and active-table cleanup

## 1. Test ID và tên testcase

* **ID:** T12
* **Tên:** Idle timeout + finalize + xóa khỏi active-flow table
* **Nhóm:** Flow/Connection Tracker (Bài tập 2)

## 2. Mục tiêu

Xác minh flow hết hạn theo cấu hình idle timeout (TCP/UDP riêng) được
finalize/xuất và **loại khỏi** active-flow table; packet đến sau đó tạo flow mới
với `flow_id` mới. Kiểm thử bằng **event timestamp xác định**, không chờ thời
gian thật.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Hết hạn theo timestamp | `flow/tracker.py::FlowTracker._expire` (dòng 579) |
| Gọi expire trong `process` | `flow/tracker.py::FlowTracker.process` (dòng 204) |
| Finalize + xóa | `flow/tracker.py::FlowTracker._finalize` (dòng 603) |
| Số flow active | `flow/tracker.py::FlowTracker.active_flow_count` (dòng 262) |
| Test method | `tests/test_assignment2_tracker.py::TrackerTimeoutTestCase::test_tcp_idle_timeout` |
| Test bổ trợ | `::test_udp_idle_timeout`, `::test_within_timeout_no_expiry` |

## 4. Input và cách tái hiện

Cấu hình `PipelineConfig(tcp_idle_timeout=10.0, udp_idle_timeout=5.0)`.

```text
1. 1.1.1.1:1000 -> 2.2.2.2:80  SYN  ts=100.0   → tạo flow
2. 1.1.1.1:1000 -> 2.2.2.2:80  ACK  ts=111.0   → 111 - 100 = 11 > 10 (timeout)
```

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerTimeoutTestCase -v
```

Fixture E2E: `TEST/assignment_2/input_mixed.pcap` với `--tcp-idle-timeout 5
--udp-idle-timeout 3`; packet cuối nằm ở t = t0 + 200 nên mọi flow trước đó hết hạn.

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Packet thứ hai (sau idle) trả về 1 record của flow cũ với
   `finalization_reason == "timeout"`.
2. Flow cũ bị xóa khỏi active table; packet mới thuộc flow **mới** cùng 5-tuple
   nhưng `flow_id` khác.
3. `active_flow_count() == 1` sau khi xử lý (chỉ còn flow mới).
4. Trong idle window (chưa vượt timeout) → không expire (`records == []`).
5. UDP cũng timeout theo `udp_idle_timeout` riêng.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T12_tracker_timeout.log`):

```text
Ran 3 tests in 0.000s
OK
```

Assertions:
* `test_tcp_idle_timeout`: sau packet ts=111, `len(records) == 1`,
  `records[0]["finalization_reason"] == "timeout"`, state `HANDSHAKE`;
  `active_flow_count() == 1`; `flush()` trả 1 flow với `flow_id` **khác**
  `records[0]["flow_id"]`.
* `test_udp_idle_timeout`: timeout sau 6 > 5 giây.
* `test_within_timeout_no_expiry`: `records == []`, vẫn 1 flow khi trong window.

Bằng chứng E2E `TEST/assignment_2/result_flows.jsonl`: 5/7 flow có
`finalization_reason=timeout` (L2, L3, L4, L5, L6); flow cũ bị loại, chỉ còn flow
mới nhất khi kết thúc.

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: `process` gọi `_expire(timestamp)` **trước** khi tạo/cập nhật
  flow; `_expire` so `now - flow.last_seen > timeout` nên ts=111 vượt 10 → finalize
  reason `"timeout"`. Test assert đúng phần tử và reason.
* Tiêu chí 2: `_finalize` gọi `self.flows.pop(flow.key)` → loại khỏi active
  table; `_generation` tăng nên `flow_id` mới khác. Test assert
  `flows[0]["flow_id"] != records[0]["flow_id"]`.
* Tiêu chí 3: test assert `active_flow_count() == 1`.
* Tiêu chí 4: `test_within_timeout_no_expiry` assert không có record.
* Tiêu chí 5: timeout tính theo protocol (`tcp_idle_timeout` vs `udp_idle_timeout`)
  trong `_expire`. E2E cho thấy cả TCP và UDP đều có record reason `timeout`.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerTimeoutTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T12_tracker_timeout.log`
* JSONL: `TEST/assignment_2/result_flows.jsonl` dòng 2, 3, 4, 5, 6 (reason `timeout`)
* Test method: `TrackerTimeoutTestCase::test_tcp_idle_timeout`,
  `::test_udp_idle_timeout`, `::test_within_timeout_no_expiry`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Timeout dùng timestamp của **event** (không dùng wall clock), nên test tất
  định và replay PCAP offline không cần chờ.
* Flow chỉ một chiều FIN và không có packet tiếp theo sẽ hết hạn theo timeout
  (finalize reason `timeout`), không tự chuyển `CLOSED`.
* `flush()` cuối capture finalize các flow còn lại với reason `flush`.
