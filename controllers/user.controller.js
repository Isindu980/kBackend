import User from "../models/user.model.js";
import { errorHandler } from "../utils/error.js";
import bcryptjs from 'bcryptjs';
// import { logUserActivity } from '../utils/activityLogger.js';

export const test = (req, res) => {
    res.json({ message: 'Backend is working!' });
};

// Fetch all users
export const getAllUsers = async (req, res, next) => {
    try {
        const users = await User.find(); // Retrieve all users from the database
        res.status(200).json(users);
    } catch (error) {
        return next(errorHandler(500, "Unable to fetch users!"));
    }
};

// Update user
export const updateUser = async (req, res, next) => {
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

        // Uncomment if activity logger is implemented
        // await logUserActivity(updatedUser._id, updatedUser.username, 'Updated Profile');
    } catch (error) {
        return next(errorHandler(500, "Error updating user!"));
    }
};

// Delete user
export const deleteUser = async (req, res, next) => {
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
