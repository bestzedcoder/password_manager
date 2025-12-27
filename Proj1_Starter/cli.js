"use strict";

const fs = require("fs");
const readline = require("readline");
const { Keychain } = require("./password-manager");

const DB_FILE = "./database.json";
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const question = (query) =>
  new Promise((resolve) => rl.question(query, resolve));

async function main() {
  console.log("=== CHƯƠNG TRÌNH QUẢN LÝ MẬT KHẨU ===");

  let keychain;
  let masterPassword = await question("Nhập mật khẩu chủ của bạn: ");

  if (fs.existsSync(DB_FILE)) {
    console.log("Phát hiện dữ liệu cũ, đang tiến hành nạp...");
    try {
      const savedData = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
      keychain = await Keychain.load(
        masterPassword,
        savedData.repr,
        savedData.checksum
      );
      console.log("✅ Nạp dữ liệu thành công!");
    } catch (e) {
      console.error(
        "❌ Lỗi: Không thể nạp dữ liệu (Sai mật khẩu hoặc file bị hỏng)."
      );
      process.exit(1);
    }
  } else {
    console.log("Chưa có database, đang tạo mới...");
    keychain = await Keychain.init(masterPassword);
    console.log("✅ Khởi tạo Keychain mới thành công!");
  }

  while (true) {
    console.log("\n--- MENU ---");
    console.log("1. Thêm/Cập nhật mật khẩu (set)");
    console.log("2. Lấy mật khẩu (get)");
    console.log("3. Xóa bản ghi (remove)");
    console.log("4. Lưu và Thoát (dump & save)");
    console.log("5. Thoát không lưu");

    const choice = await question("Chọn tính năng (1-5): ");

    switch (choice) {
      case "1":
        const domain = await question("Nhập tên miền (vd: facebook.com): ");
        const password = await question("Nhập mật khẩu: ");
        await keychain.set(domain, password);
        console.log(`✅ Đã lưu mật khẩu cho ${domain}`);
        break;

      case "2":
        const searchDomain = await question("Nhập tên miền cần tìm: ");
        const result = await keychain.get(searchDomain);
        if (result) {
          console.log(`🔑 Mật khẩu của ${searchDomain} là: ${result}`);
        } else {
          console.log("⚠️ Không tìm thấy tên miền này.");
        }
        break;

      case "3":
        const delDomain = await question("Nhập tên miền cần xóa: ");
        const deleted = await keychain.remove(delDomain);
        console.log(deleted ? "✅ Đã xóa." : "⚠️ Không tìm thấy.");
        break;

      case "4":
        console.log("Đang đóng gói và lưu dữ liệu...");
        const [repr, checksum] = await keychain.dump();
        const dataToSave = JSON.stringify({ repr, checksum }, null, 2);
        fs.writeFileSync(DB_FILE, dataToSave);
        console.log(`✅ Đã lưu vào file ${DB_FILE}. Tạm biệt!`);
        rl.close();
        return;

      case "5":
        console.log("Đã thoát.");
        rl.close();
        return;

      default:
        console.log("❌ Lựa chọn không hợp lệ.");
    }
  }
}

main().catch(console.error);
