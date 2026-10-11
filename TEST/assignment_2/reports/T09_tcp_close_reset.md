# T09 — TCP FIN/ACK close and RST reset

## 1. Test ID và tên testcase

* **ID:** T09
* **Tên:** TCP close (`FIN`) và reset (`RST`)
* **Nhóm:** Flow/Connection Tracker (Bài tập 2)

## 2. Mục tiêu

Xác minh luồng FIN/ACK đưa flow qua `CLOSING` rồi `CLOSED` (khi cả hai chiều
gửi FIN), và `RST` đưa flow về `RESET` (terminal), với `finalization_reason`
phù hợp schema và flow được xuất/loại khỏi active table.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Xử lý FIN/RST | `flow/tracker.py::FlowTracker._update_tcp_state` (dòng 482) |
| Kết thúc terminal + xuất | `flow/tracker.py::FlowTracker.process` (dòng 204) |
| Finalize | `flow/tracker.py::FlowTracker._finalize` (dòng 603) |
| Test method | `tests/test_assignment2_tracker.py::TrackerCloseTestCase::test_fin_both_directions_closes_immediately` |
| Test bổ trợ | `::test_fin_moves_to_closing`, `::test_rst_is_terminal` |

## 4. Input và cách tái hiện

FIN hai chiều:

```text
1. 1.1.1.1:100 -> 2.2.2.2:200  flags=A   ts=1.0
2. 2.2.2.2:200 -> 1.1.1.1:100  flags=A   ts=1.1
3. 1.1.1.1:100 -> 2.2.2.2:200  flags=FA  ts=1.2   (FIN chiều A)
4. 2.2.2.2:200 -> 1.1.1.1:100  flags=FA  ts=1.3   (FIN chiều B)
```

RST:

```text
RST từ 2.2.2.2:200 -> 1.1.1.1:100 với flags=R
```

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerCloseTestCase -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Sau FIN chiều thứ nhất: flow ở `CLOSING` (chưa xuất, vẫn active).
2. Sau FIN chiều thứ hai: record `state == "CLOSED"`,
   `finalization_reason == "closed"`, `FIN_count == 2`, và flow bị xóa khỏi
   active table (`active_flow_count() == 0`).
3. RST: record `state == "RESET"`, `finalization_reason == "reset"`,
   `RST_count == 1`, flow bị xóa khỏi active table.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T09_tracker_close.log`):

```text
Ran 3 tests in 0.001s
OK
```

Assertions:
* `test_fin_both_directions_closes_immediately`: giữa hai FIN → `records == []`;
  sau FIN thứ hai → `state == "CLOSED"`, `finalization_reason == "closed"`,
  `FIN_count == 2`, `active_flow_count() == 0`.
* `test_fin_moves_to_closing`: sau một FIN → state `CLOSING`.
* `test_rst_is_terminal`: `state == "RESET"`, `finalization_reason == "reset"`,
  `RST_count == 1`, `active_flow_count() == 0`.

Bằng chứng E2E `TEST/assignment_2/result_flows.jsonl`:
* L1: `state=CLOSED ... fin=2 reason=closed` (flow handshake + FIN).
* L7: `state=RESET ... rst=1 reason=reset` (flow kết thúc bằng RST).

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: `_update_tcp_state` khi gặp FIN và `state not in TERMINAL_STATES`
  chuyển sang `CLOSING`; `test_fin_moves_to_closing` xác nhận.
* Tiêu chí 2: khi `len(flow.fin_directions) >= 2` → `CLOSED`; `process` thấy
  state terminal nên gọi `_finalize(..., "closed")`, xóa khỏi `self.flows`.
  Test xác nhận record và `active_flow_count() == 0`.
* Tiêu chí 3: nhánh `if rst:` đặt `STATE_RESET` và `return`; `process` finalize
  với reason `"reset"`. Test xác nhận.
* E2E xác nhận cả hai đường đi (CLOSED và RESET) trên PCAP thật (`result_flows.jsonl`
  L1 và L7).

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerCloseTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T09_tracker_close.log`
* JSONL: `TEST/assignment_2/result_flows.jsonl` dòng 1 (CLOSED), dòng 7 (RESET)
* Test method: `TrackerCloseTestCase::test_fin_both_directions_closes_immediately`,
  `::test_fin_moves_to_closing`, `::test_rst_is_terminal`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Quy tắc đóng tài liệu hóa: `CLOSING` khi có ít nhất một FIN; `CLOSED` khi cả
  hai chiều đã gửi FIN. Nếu chỉ một FIN thì flow không đóng ngay mà chờ FIN còn
  lại hoặc hết idle timeout (khi đó finalize reason = `timeout`).
* `RST` terminal thắng mọi cờ khác trong cùng packet.
