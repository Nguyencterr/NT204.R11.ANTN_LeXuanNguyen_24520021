# T14 — Malformed / invalid / unsupported events do not crash

## 1. Test ID và tên testcase

* **ID:** T14
* **Tên:** Malformed/invalid/unsupported events handled safely
* **Nhóm:** Preprocessor + Pipeline (Bài tập 2)

## 2. Mục tiêu

Xác minh một event lỗi (thiếu field, sai kiểu, payload không hợp lệ) **không**
làm dừng pipeline; trạng thái/lý do/action được gắn đúng, và event kế tiếp vẫn
được xử lý bình thường. Kiểm tra cả đường đi `skip` theo policy.

## 3. Code liên quan

| Thành phần | Đường dẫn / hàm |
| --- | --- |
| Gán status/action/reason | `preprocessor/preprocessor.py::preprocess_event` (dòng 144) |
| Isolate lỗi per-event | `pipeline/pipeline.py::IdsPipeline.process` (dòng 39) |
| Policy skip | `config.py` (`POLICY_SKIP`), `preprocess_event` |
| Test method | `tests/test_assignment2_pipeline.py::TrackerMalformedTestCase::test_invalid_event_then_valid_event` |
| Test bổ trợ | `::test_truncated_dict_input`, `PipelineEndToEndTestCase::test_invalid_policy_skip` |

## 4. Input và cách tái hiện

Event lỗi hoàn toàn:

```python
{"packet_id": None, "timestamp": "oops"}
```

Event thiếu transport/application nhưng có IP/timestamp:

```python
{"packet_id": 1, "timestamp": 5.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
```

Event sai IP với policy `skip`.

Lệnh chạy thực tế:

```bash
.venv/bin/python -m unittest \
  tests.test_assignment2_pipeline.TrackerMalformedTestCase \
  tests.test_assignment2_pipeline.PipelineEndToEndTestCase.test_invalid_policy_skip -v
```

## 5. Kết quả mong đợi (tiêu chí PASS)

1. Event lỗi hoàn toàn (policy mặc định `mark`) → `preprocess_status == "invalid"`,
   `processing_action == "mark"`, có `preprocess_reason`, **không** exception.
2. Event kế tiếp (TCP SYN hợp lệ) vẫn được xử lý và trả về dict với
   `preprocess_status == "partial"`.
3. Event chỉ thiếu optional → `partial`, `processing_action == "keep"`.
4. Policy `skip` với event sai IP → `process()` trả `None`, `skipped_count` tăng.
5. Pipeline không crash; các event sau vẫn chạy.

## 6. Kết quả thực tế

Unit test (log `TEST/assignment_2/evidence/run_T14_pipeline_malformed.log`):

```text
Ran 3 tests in 0.000s
OK
```

Assertions:
* `test_invalid_event_then_valid_event`: event 1 →
  `preprocess_status == STATUS_INVALID`, `processing_action == "mark"`; event 2 →
  `preprocess_status == "partial"`, `processed_count == 2`.
* `test_truncated_dict_input`: thiếu transport/application →
  `processing_action == "keep"`, `preprocess_status == "partial"`.
* `test_invalid_policy_skip`: `process(bad_ip_event) is None`,
  `skipped_count == 1`.

Smoke CLI: fixture có payload lỗi UTF-8 (packet_id 13) vẫn xử lý tiếp tới 15
packet ("15 written, 0 skipped" trong `evidence/run_smoke_cli.log`).

## 7. Giải thích vì sao hoàn thành

* Tiêu chí 1: event thiếu `packet_id`/`timestamp`/`src_ip`/`dst_ip` → `errors`
  không rỗng → `STATUS_INVALID`; policy `mark` (mặc định) → action `mark`;
  `preprocess_reason` chứa danh sách lỗi. Test assert trực tiếp.
* Tiêu chí 2: Pipeline `process` gọi lại cho event 2; test assert `processed_count == 2`
  sau hai lần gọi, chứng minh event lỗi không chặn event sau.
* Tiêu chí 3: `test_truncated_dict_input` assert `keep`/`partial`.
* Tiêu chí 4: policy `skip` → `action == ACTION_SKIP`, pipeline trả `None` và
  tăng `skipped_count`.
* Tiêu chí 5: `IdsPipeline.process` bọc decode+preprocess trong `try/except`,
  nên lỗi bất ngờ cũng chỉ ảnh hưởng một event.

## 8. Bằng chứng

* Lệnh: `.venv/bin/python -m unittest tests.test_assignment2_pipeline.TrackerMalformedTestCase tests.test_assignment2_pipeline.PipelineEndToEndTestCase.test_invalid_policy_skip -v`
* Log: `TEST/assignment_2/evidence/run_T14_pipeline_malformed.log`
* Log smoke: `TEST/assignment_2/evidence/run_smoke_cli.log`
* Điểm lỗi liên quan trong JSONL: `TEST/assignment_2/result_events.jsonl` dòng 13
  (`decode_status = "partial"`, `preprocess_status = "partial"`)
* Test method: `TrackerMalformedTestCase::test_invalid_event_then_valid_event`,
  `::test_truncated_dict_input`, `PipelineEndToEndTestCase::test_invalid_policy_skip`.

## 9. Trạng thái

**PASS**

## 10. Giới hạn và ghi chú

* Event invalid theo policy `mark` **vẫn được ghi ra** output (có cờ), không bị
  bỏ; chỉ policy `skip` mới loại khỏi output/tracker. Đây là cấu hình có chủ đích.
* Với policy `skip`, event invalid không vào tracker nên không tạo flow.
