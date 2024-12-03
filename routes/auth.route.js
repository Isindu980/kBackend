import express from 'express';
import { signup, signin, google, signout, verifyOtp } from '../controllers/auth.controller.js';

const router = express.Router();

router.post('/signup', signup);      // Route to handle user signup and send OTP
router.post('/signin', signin);      // Route to handle user login
router.post('/google', google);      // Route for Google sign-in
router.post('/verifyOtp', verifyOtp); // Route to verify OTP
router.get('/signout', signout);     // Route to handle user signout

export default router;
