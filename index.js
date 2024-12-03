import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import userRoutes from './routes/user.route.js';
import authRoutes from './routes/auth.route.js';
import cookieParser from 'cookie-parser';
//import adminRoutes from './routes/admin.route.js';

dotenv.config();

mongoose.connect(process.env.MONGO).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.log(error);
});

const app = express();

/*mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});*/



app.use(express.json());
app.use(cookieParser());

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

app.use("/backend/user", userRoutes);
app.use("/backend/auth", authRoutes);
//app.use('/backend/admin', adminRoutes);

app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  return res.status(statusCode).json({ 
    success: false,
    message,
    statusCode,
  });
}
);

// Start the server
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});