import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import userRoutes from './routes/user.route.js';
import authRoutes from './routes/auth.route.js';
import cookieParser from 'cookie-parser';

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

app.use('/backend/user', userRoutes);
app.use('/backend/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});