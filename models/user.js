const { randomBytes, scryptSync, timingSafeEqual } = require("crypto");
const { Schema, model } = require("mongoose");
const { createTokenForUser } = require("../service/authentication");

const userSchema = new Schema({
  fullName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  salt: {
    type: String,
  },
  password: {
    type: String,
    required: true,
  },
  profileImageURL: {
    type: String,
    default: "/images/default.png",
  },
  role: {
    type: String,
    enum: ["USER", "ADMIN"],
    default: "USER",
  },
  lastLoginAt: {
    type: Date,
  },
}, { timestamps: true });

userSchema.pre("save", function (next) {
  const user = this;

  if (user.isModified("email") && typeof user.email === "string") {
    user.email = user.email.toLowerCase();
  }

  if (!user.isModified("password")) return next();

  const salt = randomBytes(16).toString("hex");
  const hashedPassword = scryptSync(user.password, salt, 64).toString("hex");

  user.salt = salt;
  user.password = hashedPassword;

  next();
});

userSchema.static(
  "matchPasswordAndGenerateToken",
  async function (email, password) {
    const normalizedEmail = typeof email === "string" ? email.toLowerCase() : email;
    const user = await this.findOne({ email: normalizedEmail });
    if (!user) throw new Error("User not found!");

    if (!user.salt || !user.password) {
      throw new Error("Credentials not set up correctly");
    }

    const storedHash = Buffer.from(user.password, "hex");
    const userProvidedHash = scryptSync(password, user.salt, storedHash.length);

    if (!timingSafeEqual(storedHash, userProvidedHash)) throw new Error("Incorrect Password");

    user.lastLoginAt = new Date();
    await user.save({ validateBeforeSave: false });

    const token = createTokenForUser(user);
    return token;
  }
);

const User = model("user", userSchema);

module.exports = User;
