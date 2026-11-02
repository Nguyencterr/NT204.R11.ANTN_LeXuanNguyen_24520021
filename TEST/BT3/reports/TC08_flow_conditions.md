# TC08 — `flow:to_server` / `to_client` / `established` từ tracker thật

- **Mục:** 4.4 Rule Matching Engine + adapter `flow/context.py`
- **Trạng thái:** PASS
- **Test class:** `tests.test_assignment3_matching.TC08FlowStateTestCase`
- **Lệnh chạy:**

```bash
.venv/bin/python -m unittest tests.test_assignment3_matching.TC08FlowStateTestCase -v
```

- **Kết quả thực tế:** `Ran 6 tests ... OK`, exit 0.

## Mục tiêu

Rule `flow:` chỉ được đánh giá từ context do Flow Tracker thật cung cấp:

- TCP SYN xác định client;
- nếu không có SYN, dùng port server nổi tiếng, rồi heuristic port thấp;
- không có context/không rõ vai trò ⇒ **không** được bịa `to_server`/`to_client`;
- `established` của TCP dựa trên `ever_established`; UDP `OPEN` được tài liệu hoá là
  `established` (không mô phỏng handshake TCP).

## Fixture / input

`TEST/BT3/rules/flow_rules.rules` (5 rule) và event tổng hợp có timestamp xác định.

## Tiêu chí PASS

1. `role_source` ghi rõ nguồn suy luận (`tcp_syn`, `well_known_port`, `lower_port`,
   `unknown`).
2. Gói SYN trong handshake: `not_established` khớp, `established` chưa khớp.
3. Sau handshake: `to_server,established` khớp gói client → server.
4. Gói server → client khớp `to_client`.
5. Thiếu flow context: rule yêu cầu `flow` trả `NO_MATCH`, reason nêu không thể đánh giá;
   không tự tạo state.
6. UDP flow `OPEN`: `established` được coi là true theo chính sách đã tài liệu hoá.

## Kết quả thực tế

- 6/6 test OK.
- `to_server,established` MATCH đúng gói thuận sau handshake.
- `to_client` MATCH đúng gói phản hồi.
- Gói SYN: rule `established` NO_MATCH; rule `not_established` MATCH.
- Event không có context: NO_MATCH với lý do “rule requires flow context…”.

## Bằng chứng

- `TEST/BT3/evidence/test_logs/run_TC08.log`

## Ghi chú / hạn chế

- Vai trò client/server là **suy luận có bằng chứng**, không phải ground truth của giao thức;
  `role_source` giúp giải thích mỗi quyết định.
- UDP không có khái niệm “established” thật; đây là quy ước của Bài 3 và được nêu rõ trong
  README.
