import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

dotenv.config();

const MONGO = process.env.MONGO;
if (!MONGO) {
  console.error('MongoDB connection string is missing in environment variables.');
  process.exit(1);
}

mongoose
  .connect(MONGO)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  });

const app = express();
app.use(express.json());
app.use(cookieParser());

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePic: {
    type: String,
    default: "https://thumbs.dreamstime.com/b/default-avatar-profile-icon-social-media-user-image-gray-blank-silhouette-vector-illustration-305503988.jpg",
  },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
  username: { type: String, required: true },
  hashedPassword: { type: String, required: true },
  email: { type: String, required: true },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});

const OTP = mongoose.model('OTP', otpSchema);

const errorHandler = (statusCode, message) => {
  const error = new Error();
  error.statusCode = statusCode;
  error.message = message;
  return error;
};

const verifyToken = (req, res, next) => {
  const token = req.cookies.my_token;
  if (!token) return next(errorHandler(401, 'You are not authenticated!'));

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(errorHandler(403, 'Token is not valid!'));
    req.user = user;
    next();
  });
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const signup = async (req, res, next) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return next(errorHandler(400, "User already exists"));

    const hashedPassword = bcryptjs.hashSync(password, 10);
    const otpCode = crypto.randomInt(100000, 999999).toString();

    const otpEntry = new OTP({
      username,
      hashedPassword,
      email,
      code: otpCode,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });
    await otpEntry.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email - OTP Code',
      text: `Your OTP code is ${otpCode}. Unavailable in 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    res.status(201).json({ message: 'Signup successful! Please verify your email with the OTP.' });
  } catch (error) {
    next(error);
  }
};

const verifyOtp = async (req, res, next) => {
  const { email, otp } = req.body;
  try {
    const otpEntry = await OTP.findOne({ email, code: otp });
    if (!otpEntry) return res.status(400).json({ success: false, message: 'Invalid OTP' });
    if (otpEntry.expiresAt < Date.now()) return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });

    const newUser = new User({
      username: otpEntry.username,
      email,
      password: otpEntry.hashedPassword,
    });
    await newUser.save();
    await OTP.deleteOne({ _id: otpEntry._id });
    res.status(200).json({ success: true, message: 'OTP verified. Account created successfully.' });
  } catch (error) {
    next(error);
  }
};

const signin = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const validUser = await User.findOne({ email });
    if (!validUser) return next(errorHandler(404, "User not Found"));

    const isValidPassword = bcryptjs.compareSync(password, validUser.password);
    if (!isValidPassword) return next(errorHandler(401, "Wrong Credentials"));

    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET);
    const { password: hashedPassword, ...rest } = validUser._doc;
    const expiryDate = new Date(Date.now() + 3600000);
    res.cookie("my_token", token, { httpOnly: true, expires: expiryDate }).status(200).json(rest);
  } catch (error) {
    next(error);
  }
};

const google = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
      const { password: hashedPassword, ...rest } = user._doc;
      const expiryDate = new Date(Date.now() + 3600000);
      res.cookie("my_token", token, { httpOnly: true, expires: expiryDate }).status(200).json(rest);
    } else {
      const generatedPassword = Math.random().toString(36).slice(-8);
      const hashedPassword = bcryptjs.hashSync(generatedPassword, 10);
      const newUser = new User({
        username: req.body.name.split(" ").join("").toLowerCase() + Math.random().toString(36).slice(-8),
        email: req.body.email,
        password: hashedPassword,
        profilePic: req.body.photo,
      });
      await newUser.save();
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
      const { password: hashedPassword2, ...rest } = newUser._doc;
      const expiryDate = new Date(Date.now() + 3600000);
      res.cookie("my_token", token, { httpOnly: true, expires: expiryDate }).status(200).json(rest);
    }
  } catch (error) {
    next(error);
  }
};

const signout = (req, res) => {
  res.clearCookie("my_token").status(200).json('Signout success!');
};

const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find();
    res.status(200).json(users);
  } catch (error) {
    return next(errorHandler(500, "Unable to fetch users!"));
  }
};

const updateUser = async (req, res, next) => {
  if (req.user.id !== req.params.id) {
    return next(errorHandler(401, "You can update only your account!"));
  }
  try {
    if (req.body.password) {
      req.body.password = bcryptjs.hashSync(req.body.password, 10);
    }
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          username: req.body.username,
          email: req.body.email,
          password: req.body.password,
          profilePic: req.body.profilePic,
        },
      },
      { new: true }
    );
    const { password, ...rest } = updatedUser._doc;
    res.status(200).json(rest);
  } catch (error) {
    return next(errorHandler(500, "Error updating user!"));
  }
};

const deleteUser = async (req, res, next) => {
  if (req.user.id !== req.params.id) {
    return next(errorHandler(401, "You can delete only your account!"));
  }
  try {
    await User.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: "Account has been deleted!" });
  } catch (error) {
    return next(errorHandler(500, "Error deleting user!"));
  }
};

app.post('/api/auth/signup', signup);
app.post('/api/auth/verify-otp', verifyOtp);
app.post('/api/auth/signin', signin);
app.post('/api/auth/google', google);
app.post('/api/auth/signout', signout);
app.get('/api/user', verifyToken, getAllUsers);
app.put('/api/user/:id', verifyToken, updateUser);
app.delete('/api/user/:id', verifyToken, deleteUser);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});