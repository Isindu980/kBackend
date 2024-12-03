import mongoose from 'mongoose';

const otpSchema = new mongoose.Schema({
  username: { type: String, required: true },
  hashedPassword: { type: String, required: true },
  email: { type: String, required: true },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});

export default mongoose.model('OTP', otpSchema);