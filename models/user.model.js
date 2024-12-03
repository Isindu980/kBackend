import mongoose from "mongoose";


const userSchema = new mongoose.Schema({
    username:{
        type: String,
        required: true,
        unique: true,
    },
    email:{
        type: String,
        required: true,
        unique: true,
    },
    password:{
        type: String,
        required: true,
    },
    profilePic:{
        type: String,
        default: "https://thumbs.dreamstime.com/b/default-avatar-profile-icon-social-media-user-image-gray-blank-silhouette-vector-illustration-305503988.jpg",
    },
},{timestamp: true});

const User = mongoose.model('User', userSchema);

export default User;