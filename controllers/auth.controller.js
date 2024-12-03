import User from '../models/user.model.js';
import bcryptjs from 'bcryptjs';
import { errorHandler } from '../utils/error.js';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import dotenv from 'dotenv';
import OTP from '../models/otp.model.js'; 
//import { logUserActivity } from '../utils/activityLogger.js';
dotenv.config();


import { log } from 'console';

// Nodemailer configuration for sending OTP email
const transporter = nodemailer.createTransport({
  service: 'gmail',  // Replace with your email provider if not Gmail
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Signup function with OTP email
export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(errorHandler(400, "User already exists"));
    }

    
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


export const verifyOtp = async (req, res, next) => {
  const { email, otp } = req.body;

  try {
    // Find the OTP entry by email and OTP code
    const otpEntry = await OTP.findOne({ email, code: otp });

    // Check if OTP entry exists
    if (!otpEntry) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    // Check if OTP is expired
    if (otpEntry.expiresAt < Date.now()) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
    }

    // Create new user based on OTP entry data
    const newUser = new User({
      username: otpEntry.username,
      email,
      password: otpEntry.hashedPassword,
    });

    await newUser.save();

    // Delete the OTP entry by its ID after successful verification
    await OTP.deleteOne({ _id: otpEntry._id });
    //await logUserActivity(newUser._id, newUser.username, 'Account Created');

    res.status(200).json({ success: true, message: 'OTP verified. Account created successfully.' });
  } catch (error) {
    next(error);
  }
};



export const signin = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const validUser = await User.findOne({ email });
    if (!validUser) return next(errorHandler(404, "User not Found"));

    const isValidPassword = bcryptjs.compareSync(password, validUser.password);
    if (!isValidPassword) return next(errorHandler(401, "Wrong Credentials"));

    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET);
    const { password: hashedPassword, ...rest } = validUser._doc;

    const expiryDate = new Date(Date.now() + 3600000); 
    res.cookie("my_token", token, { httpOnly: true, expires: expiryDate })
       .status(200)
       .json(rest);
  } catch (error) {
    next(error);
  }
};


export const google = async (req, res, next) => {
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


export const signout = (req, res) => {
  res.clearCookie("my_token").status(200).json('Signout success!');
};

