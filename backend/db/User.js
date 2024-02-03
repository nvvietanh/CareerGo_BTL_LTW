const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
require("mongoose-type-email");

let schema = new mongoose.Schema(
  {
    email: {
      type: mongoose.SchemaTypes.Email,
      unique: true,
      lowercase: true,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      enum: ["recruiter", "applicant"],
      required: true,
    },
  },
  { collation: { locale: "en" } }
);

// Password hashing
// Mã hóa mật khẩu trước khi lưu vào CSDL
// Nếu mật khẩu thay đổi thì phải mã hóa và lưu mật khẩu đã mã hóa mới, ko thì ko làm gì mật khẩu.
schema.pre("save", function (next) {
  let user = this;

  // if the data is not modified
  if (!user.isModified("password")) {
    return next();
  }

  // Hàm băm để mã hóa mật khẩu
  bcrypt.hash(user.password, 10, (err, hash) => {
    if (err) {
      return next(err);
    }
    user.password = hash;
    next();
  });
});

// Password verification upon login
// So sánh password do người dùng nhập và password trong CSDL
schema.methods.login = function (password) {
  let user = this; // đây là đối tượng user lấy trong CSDL (trùng với email do người dùng nhập)

  return new Promise((resolve, reject) => {
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        reject(err); // nếu có lỗi thì gọi reject promise
      }
      if (result) {
        resolve(); // nếu có kết quả thì gọi resolve promise
      } else {
        reject(); // nếu không có kết quả thì gọi reject promise
      }
    });
  });
};

module.exports = mongoose.model("UserAuth", schema);
