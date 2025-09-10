const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(helmet());

// ✅ CORS setup
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:3000",
  "https://restarant-app-frontend.vercel.app",
];
app.use(cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
}));

// ✅ MongoDB
const mongoURI = process.env.MONGODB_URI;
if (!mongoURI) {
  console.error("❌ MONGODB_URI missing in .env");
  process.exit(1);
}
mongoose.connect(mongoURI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((error) => console.error('❌ Error connecting MongoDB:', error));

// ✅ User schema
const userSchema = new mongoose.Schema({
  fullName: String,
  username: String,
  email: { type: String, unique: true },
  phone: String,
  address: String,
  password: String,
  otp: String,
  otpExpiry: Date,
  otpResendCooldown: Date, // Added for resend cooldown
});
const User = mongoose.model('User', userSchema);

// ✅ Configure nodemailer transporter via Gmail SMTP
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Verify transporter at startup for clearer diagnostics
transporter.verify((err, success) => {
  if (err) {
    console.error('❌ Nodemailer verify failed:', err.message);
  } else {
    console.log('✅ Nodemailer transport ready');
  }
});

// ✅ Generate and send OTP
const generateAndSendOtp = async (rawEmail) => {
  try {
    const email = (rawEmail || '').trim().toLowerCase();
    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    // Check if cooldown period is still active
    if (user.otpResendCooldown && user.otpResendCooldown > Date.now()) {
      const cooldownRemaining = Math.ceil((user.otpResendCooldown - Date.now()) / 1000);
      throw new Error(`Please wait ${cooldownRemaining} seconds before requesting a new OTP`);
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
    const otpExpiry = Date.now() + 5 * 60 * 1000; // 5 minutes
    const otpResendCooldown = Date.now() + 60 * 1000; // 1 minute cooldown

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    user.otpResendCooldown = otpResendCooldown;
    await user.save();

    // Send email
    const mailOptions = {
      from: `"Restaurant App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset OTP",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
          <h2 style="color: #6a11cb;">Password Reset OTP</h2>
          <p>Your OTP code is: <strong style="font-size: 24px; color: #2575fc;">${otp}</strong></p>
          <p>This code will expire in 5 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <hr style="border: none; border-top: 1px solid #eee;" />
          <p style="color: #777; font-size: 12px;">This is an automated message, please do not reply.</p>
        </div>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('📧 OTP sent successfully to:', email, 'messageId:', info.messageId);

    return { message: "OTP sent to email", cooldown: 60 };
  } catch (err) {
    console.error('Error sending OTP:', err.message || err);
    throw err;
  }
};

// ✅ Register
app.post('/register', async (req, res) => {
  const { fullName, username, email, phone, address, password } = req.body;
  try {
    const normalizedEmail = (email || '').trim().toLowerCase();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) return res.status(400).json({ message: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ fullName, username, email: normalizedEmail, phone, address, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Error registering user', error });
  }
});

// ✅ Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const normalizedEmail = (email || '').trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

    // Do not send password hash back
    const { password: _p, ...safeUser } = user.toObject();
    res.status(200).json({ message: 'Login successful', user: safeUser });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// ✅ Forgot Password (send OTP)
app.post('/forgot-password', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  console.log(`[Forgot Password] Request received for email: ${email}`);
  try {
    const result = await generateAndSendOtp(email);
    console.log(`[Forgot Password] OTP sent. Cooldown: ${result.cooldown || 'N/A'}s`);
    res.json(result);
  } catch (err) {
    console.error(`[Forgot Password] Error for email ${email}:`, err.message || err);
    const status = err.message === 'User not found' ? 404 : 500;
    res.status(status).json({ message: err.message || "Error sending OTP" });
  }
});

// ✅ Resend OTP
app.post('/resend-otp', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  try {
    const result = await generateAndSendOtp(email);
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: err.message || "Error resending OTP" });
  }
});

// ✅ Verify OTP
app.post('/verify-otp', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const { otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }
    if (user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP has expired" });
    }
    res.json({ message: "OTP verified successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error verifying OTP" });
  }
});

// ✅ Reset Password
app.post('/reset-password', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const { password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.otp = null;
    user.otpExpiry = null;
    user.otpResendCooldown = null;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ message: "Error resetting password" });
  }
});

// ✅ Contact
const contactSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
});
const Contact = mongoose.model('Contact', contactSchema);

app.post('/contact', async (req, res) => {
  try {
    const newContact = new Contact(req.body);
    await newContact.save();
    res.status(201).json({ message: 'Message sent successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Error saving message' });
  }
});

// ✅ Root
app.get("/", (req, res) => {
  res.send("Backend is running ✅");
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});