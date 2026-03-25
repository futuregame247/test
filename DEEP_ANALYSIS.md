# Deep Analysis `steam.run` Payloads (Static + Reverse)

Phân tích này trả lời trực tiếp câu hỏi: "các file bin chứa gì, làm gì, có check sâu hơn được không?"

## 1) Mức độ phân tích đã làm
- Static reverse ở mức PE internals + disassembly (không chạy payload trên host).
- Parse import/export/resources, entrypoint, strings, xrefs, call-sites.
- Tạo artefact kỹ thuật:
  - `deep_static_report.json`
  - `deep_pe_meta.json`
  - `payload_update_behavior_trace.txt`
  - `payload_dwmapi_behavior_trace.txt`
  - `payload_update_string_xrefs.txt`

## 2) Kết quả sâu cho từng file
## 2.1 `payload_update.bin` (dự kiến bị ghi thành `xinput1_4.dll`)
### Bằng chứng kỹ thuật
- PE x64 DLL, signed valid.
- Import DLL:
  - `CRYPT32.dll`
  - `WS2_32.dll`
  - `KERNEL32.dll`
  - `ADVAPI32.dll`
  - `SHELL32.dll`
  - `ole32.dll`
- Import mạng (đã resolve ordinal `ws2_32`):
  - `socket`, `connect`, `send`, `recv`, `getaddrinfo`, `inet_pton`, `WSAStartup`, ...
- Có string network/update:
  - `https://update.aaasn.com/version`
  - `https://update.tnkjmec.com/version`
  - `http://update.wudrm.com/version`
  - `http://update.steamcdn.com/version`
- Có string liên quan Steam IPC:
  - `Global\Valve_SteamIPC_Class`
  - `Global\Vale_SteamIPC_Class%u`
- VersionInfo giả nhãn app:
  - `CompanyName=Vale Corporation`
  - `FileDescription=Vale Dynamic Link Library`

### Nhận định hành vi
- DLL này có năng lực network rõ ràng (Winsock + URL update).
- Có dấu hiệu tương tác với Steam IPC object naming.
- Có thể là module "core/update/communication".
- Việc export nhiều hàm `cJSON_*` không chứng minh an toàn; đó chỉ là phần API/lib được export.

## 2.2 `payload_dwmapi.bin` (dự kiến bị ghi thành `dwmapi.dll`)
### Bằng chứng kỹ thuật
- PE x64 DLL, signed valid.
- Chủ yếu import `KERNEL32.dll`.
- Không có export table rõ ràng (không giống một `dwmapi.dll` chuẩn).
- Disassembly entrypoint cho thấy khi `DllMain(reason==1)` có thao tác file cụ thể:
  - string literal: `appcache\packageinfo.vdf`
  - string literal: `r+b`
  - mở file, đọc/ghi, tìm pattern byte trong buffer rồi ghi lại.
- Có chuỗi API-set + dynamic loader logic (load theo tên module/runtime API).

### Nhận định hành vi
- DLL này không phải thư viện hệ thống `dwmapi` bình thường.
- Nó có logic sửa file nội dung trong cache/package data của Steam (`packageinfo.vdf`).
- Nhiều khả năng đây là module "patcher" local data để đổi hành vi/license/package flags.

## 2.3 `version_update_*.bin`
### Bằng chứng kỹ thuật
- Không phải PE executable (`MZ` absent, `objdump` không nhận format).
- Kích thước cố định 672 bytes.
- Entropy cao (~7.69 bits/byte), không có plaintext rõ ràng.
- 3 file giống hệt hash (`aaasn/steamcdn/tnkjmec`), 1 file (`wudrm`) khác.

### Nhận định hành vi
- Đây không phải file "chạy trực tiếp".
- Rất giống blob dữ liệu mã hóa/cấu hình update mà `payload_update.bin` đọc ở runtime.

## 3) Trả lời câu hỏi "check luôn payload network/process/load DLL động được không?"
- Check sâu STATIC: làm được và đã làm (import/call-site/xref/disasm như trên).
- Check đầy đủ DYNAMIC (thực sự kết luận runtime làm gì theo thời gian): chỉ an toàn khi chạy trong VM sandbox cô lập.

Vì sao không nên chạy trực tiếp trên host hiện tại:
- Payload có khả năng thao tác file/process + network.
- Script gốc còn thêm Defender Exclusion.
- Chạy trực tiếp có thể làm bẩn hệ thống thật và mất bằng chứng sạch.

## 4) Kết luận ngắn gọn
- Đây KHÔNG phải bộ cài Steam thông thường.
- Nó là bộ can thiệp/hijack vào môi trường Steam bằng cách:
  - drop DLL vào thư mục Steam,
  - patch dữ liệu local (`packageinfo.vdf`),
  - gọi network update channel riêng.
- Không thể khẳng định "chỉ can thiệp Steam và không ảnh hưởng hệ thống".

## 5) Nếu muốn đi đến mức "100% runtime behavior"
Cần chạy trong môi trường cô lập rồi thu full telemetry:
1. VM snapshot sạch (không tài khoản thật).
2. Sysmon + Procmon + Wireshark + API monitor.
3. Chạy mẫu, capture full file/registry/process/network timeline.
4. Diff snapshot trước/sau.

---
Tài liệu này là kết quả reverse tĩnh sâu, không thực thi payload trên host.

## 6) Capability matching tự động (capa)
Đã chạy capa với rule set mở rộng (không thực thi mẫu), kết quả:

### 6.1 `payload_update.bin`
Match các capability đáng chú ý:
- socket communication (`socket/connect/send/recv`, `WSAStartup`, DNS resolve)
- create process / terminate process
- allocate/change memory protection (bao gồm RWX/RW)
- enumerate threads, suspend/resume thread
- file create/read/write/move/delete
- anti-analysis indicators (timing check, debugger related patterns)
- crypto/encoding patterns (AES/XOR/Base64/MD5, zlib signatures)

Lưu ý quan trọng:
- capa có thể match cả code thư viện (libcurl/CRT) -> có thể có false positive từng rule lẻ.
- Nhưng tổng thể vẫn củng cố mạnh việc DLL này có năng lực network + system manipulation rõ ràng.

### 6.2 `payload_dwmapi.bin`
Match chủ yếu:
- file create/read/write/clear
- parse/enumerate PE sections
- TLS runtime handling, dynamic linking
- terminate process

Kết quả này khớp với disassembly: DLL này thiên về patch local + loader/runtime helper, không thấy dấu hiệu network trực tiếp mạnh như `payload_update.bin`.

### 6.3 Artefacts capa
- `capa_payload_update.json`
- `capa_payload_dwmapi.json`
- rule set local: thư mục `capa-rules/`
