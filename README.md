# 3SCooltrans – Theo dõi giờ cấm xe

Website Node.js + Express + PostgreSQL cho nhiều nhân viên đăng nhập chung, có phân quyền quản trị viên/nhân viên.

## Tính năng
- Đăng nhập bằng tài khoản được lưu trong PostgreSQL; mật khẩu được băm bằng bcrypt.
- Cookie phiên `HttpOnly`, `SameSite=Lax`, HTTPS cookie khi `NODE_ENV=production`.
- Chống thử mật khẩu liên tục ở endpoint đăng nhập.
- Thêm/sửa/xóa thông tin xe, ngày bắt đầu/kết thúc, ghi chú.
- Trạng thái tính theo ngày kết thúc: đỏ khi quá hạn, vàng còn 0–10 ngày, xanh trên 20 ngày, xám 11–20 ngày.
- Cảnh báo hiện ngay trên trang khi xe sắp hết hạn/đã quá hạn.
- Xuất danh sách CSV.
- Quản trị viên có thể tạo và xóa tài khoản nhân viên.
- Dữ liệu chia sẻ giữa nhân viên thông qua PostgreSQL.

## Cần chuẩn bị để đưa lên mạng
1. Một dịch vụ chạy ứng dụng Node.js (ví dụ Render, Railway hoặc máy chủ riêng).
2. Một PostgreSQL database được nhà cung cấp tạo.
3. Tên miền/HTTPS (nếu dùng hosting thường cung cấp HTTPS tự động).

Tệp này **chưa được triển khai công khai**. Cần có tài khoản hosting và database của công ty để đưa lên mạng.

## Biến môi trường bắt buộc
Thiết lập trong mục Environment Variables của nhà cung cấp hosting; không lưu mật khẩu thật vào mã nguồn:
- `NODE_ENV=production`
- `DATABASE_URL` = connection string của PostgreSQL
- `SESSION_SECRET` = chuỗi ngẫu nhiên mạnh ít nhất 32 ký tự
- `BOOTSTRAP_ADMIN_USERNAME` = tên đăng nhập quản trị viên ban đầu
- `BOOTSTRAP_ADMIN_PASSWORD` = mật khẩu mạnh riêng, tối thiểu nên 12–16 ký tự

Không gửi các giá trị bí mật này vào chat hoặc đưa vào GitHub. Sau khi tài khoản quản trị đầu tiên được tạo, có thể tạo các tài khoản nhân viên trong mục “Quản lý tài khoản nhân viên”. Nếu thay đổi mật khẩu bootstrap sau khi tài khoản đã được tạo, ứng dụng không tự đổi mật khẩu tài khoản hiện hữu; nên quản lý mật khẩu qua quy trình quản trị phù hợp.

## Chạy thử trên máy tính
Cần cài Node.js 20+ và có PostgreSQL.
1. Giải nén dự án.
2. Sao chép `.env.example` thành `.env`.
3. Điền `DATABASE_URL`, `SESSION_SECRET`, `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD` trong `.env`.
4. Mở Terminal/CMD tại thư mục dự án và chạy:
   ```bash
   npm install
   npm start
   ```
5. Mở `http://localhost:3000`.

## Đưa lên Render (hướng dẫn khái quát)
1. Tạo PostgreSQL database và web service Node.js.
2. Đưa các tệp dự án lên kho Git riêng của công ty (không đưa `.env`).
3. Chọn build command `npm install`, start command `npm start`.
4. Cấu hình các biến môi trường trong trang quản trị hosting.
5. Deploy, mở URL HTTPS và đăng nhập bằng tài khoản bootstrap đã cấu hình.
6. Đăng nhập với quyền quản trị, tạo tài khoản riêng cho từng nhân viên; không dùng chung một mật khẩu.
7. Kiểm tra backup database và thử nghiệm với dữ liệu giả trước khi nhập dữ liệu vận hành thật.

## Ghi chú bảo mật
- Không có mật khẩu người dùng nào được nhúng vào HTML/JavaScript phía trình duyệt.
- Không commit `.env`, database URL hoặc `SESSION_SECRET`.
- Dùng HTTPS, mật khẩu riêng mạnh, tài khoản riêng cho từng người và bật backup database.
- Bản khởi đầu này chưa có luồng đổi/quên mật khẩu, nhật ký kiểm toán chi tiết hoặc thông báo email/SMS. Cảnh báo hiện tại hiển thị trên website khi người dùng mở trang.
