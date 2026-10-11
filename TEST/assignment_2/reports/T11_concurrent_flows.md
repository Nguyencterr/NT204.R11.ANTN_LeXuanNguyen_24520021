# T11 — Concurrent flows remain distinct

## 1. Test ID và tên testcase

* **ID:** T11
* **Tên:** Concurrent flows distinct (nhiều flow đồng thời)
* **Nhóm:** Flow/Connection Tracker (Bài tập 2)

## 2. Mục tiêu

Xác minh nhiều flow có endpoint/port khác nhau được nhận diện là **flow riêng
biệt**, có `flow_id` khác nhau, và thống kê không bị trộn; đồng thời packet của
cùng một flow cập nhật flow đó thay vì tạo trùng.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Key theo tuple | `flow/tracker.py::_canonical_key` (dòng 73) |
| Sinh `flow_id` | `flow/tracker.py::_stable_flow_id` (dòng 98) |
| Tạo/tái sử dụng flow | `flow/tracker.py::FlowTracker._get_or_create` (dòng 317) |
| Test method | `tests/test_assignment2_tracker.py::TrackerConcurrentTestCase::test_distinct_5_tuples_distinct_flows` |
| Test bổ trợ | `::test_same_flow_updates_instead_of_duplicating` |

## 4. Input và cách tái hiện

Ba flow khác 5-tuple:

```text
1. 1.1.1.1:1000 -> 2.2.2.2:80  SYN  ts=1.0
2. 1.1.1.1:2000 -> 2.2.2.2:80  SYN  ts=1.0
3. 3.3.3.3:3000 -> 2.2.2.2:80  SYN  ts=1.0
```

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerConcurrentTestCase -v
```

Fixture E2E: `TEST/assignment_2/input_mixed.pcap` có hai flow UDP DNS song song
(192.168.1.10:53000 và 192.168.1.30:53001), và nhiều flow TCP khác cổng.

## 5. Kết quả mong đợi (tiêu chí PASS)

1. `active_flow_count() == 3` sau ba packet.
2. `flush()` trả về 3 record với 3 `flow_id` **phân biệt**.
3. Packet cùng 5-tuple lặp lại **không** tạo flow mới mà cập nhật flow cũ
   (`packet_count` tăng).

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T11_tracker_concurrent.log`):

```text
Ran 2 tests in 0.000s
OK
```

Assertions:
* `test_distinct_5_tuples_distinct_flows`: `active_flow_count() == 3`,
  `len(flows) == 3`, `len({f["flow_id"] for f in flows}) == 3`.
* `test_same_flow_updates_instead_of_duplicating`: 2 packet cùng flow →
  `active_flow_count() == 1`, `packet_count == 2`.

Bằng chứng E2E `TEST/assignment_2/result_flows.jsonl`: 7 record có 7 `flow_id`
khác nhau (id ngắn: `4edd6843353d`, `f261fcd1e0c2`, `3cb44ec3ae1d`,
`7cb49b7ea552`, `9d2e4704afc7`, `0eee6a731abe`, `ff94eba308ea`), trong đó L4 và
L5 là hai flow UDP DNS song song với counters riêng
(L4 `pkts=2 fwd=1 bwd=1`, L5 `pkts=1 fwd=1 bwd=0`).

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1, 2: `_get_or_create` dùng `key = _canonical_key(...)` làm khóa
  dict, ba tuple khác nhau → ba flow; test assert số flow và tính duy nhất của
  `flow_id` bằng `set`.
* Tiêu chí 3: cùng key → `existing = self.flows.get(key)` trả về flow cũ, không
  tạo mới; test assert chỉ 1 flow và `packet_count == 2`.
* E2E: hai flow DNS song song trong cùng PCAP cho thấy counters tách biệt, không
  trộn.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_tracker.TrackerConcurrentTestCase -v`
* Log: `TEST/assignment_2/evidence/run_T11_tracker_concurrent.log`
* JSONL: `TEST/assignment_2/result_flows.jsonl` (7 dòng, 7 `flow_id`)
* Test method: `TrackerConcurrentTestCase::test_distinct_5_tuples_distinct_flows`,
  `::test_same_flow_updates_instead_of_duplicating`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Phân biệt flow dựa trên 5-tuple; hai kết nối cùng 5-tuple nhưng ở hai thời
  điểm khác nhau (sau timeout) được coi là hai flow nhờ `generation` (xem T12).
* Tracker chỉ quản lý TCP/UDP; protocol khác bị bỏ qua (không tạo flow).
