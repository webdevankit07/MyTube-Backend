import asyncHandler from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js";
import uploadOnCloudinary from "../services/cloudinary.js";
import ApiResponse from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import ApiError, { throwApiError } from "../utils/ApiError.js";

// generate Access and Refresh Token....
const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(
            500,
            "Error while generating access and refresh token"
        );
    }
};

// Controllers.......
const registerUser = asyncHandler(async (req, res) => {
    // get user details from client....
    const { userName, email, fullName, password } = req.body;
    throwApiError(
        [userName, email, fullName, password].some(
            (field) => field?.trim() === "" || !field
        ),
        400,
        "All fields are required"
    );

    // check if user already exists : username, email....
    const existedUser = await User.findOne({ $or: [{ userName }, { email }] });
    throwApiError(existedUser, 409, "User already exists");

    // check for images and validate avatar...
    let avatarLocalPath;
    let coverImageLocalPath;

    req.files.avatar && (avatarLocalPath = req.files.avatar[0].path); // set avatar and CoverImage local path
    req.files.coverImage &&
        (coverImageLocalPath = req.files.coverImage[0].path);
    console.log(avatarLocalPath, coverImageLocalPath);
    throwApiError(!avatarLocalPath, 400, "Avatar file is required");

    // upload image to cloudinary.....
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    throwApiError(!avatar, 400, "Error while uploading avatar to cloudinary");

    // create user object - create entry in db.....
    const user = await User.create({
        fullName,
        userName: userName.toLowerCase(),
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
    });

    // remove password and refresh token fields
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );
    throwApiError(!createdUser, 500, "Error while finding created user");

    return res
        .status(201)
        .json(
            new ApiResponse(200, createdUser, "User Registered Successfully")
        );
});

const loginUser = asyncHandler(async (req, res) => {
    const { userName, email, password } = req.body;
    throwApiError(!userName && !email, 400, "username or email is required");

    // find the user
    const user = await User.findOne({ $or: [{ userName }, { email }] });
    throwApiError(!user, 400, "User does not exist");

    // password chek
    const isPasswordValid = await user.isPasswordCorrect(password);
    throwApiError(!isPasswordValid, 402, "email or password is wrong");

    // access and refresh token
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
        user._id
    );

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    // send cookie
    const options = { httpOnly: true, secure: true };
    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken,
                },
                "User logged in successfully"
            )
        );
});

const logOutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, { $unset: { refreshToken: 1 } });

    const options = { httpOnly: true, secure: true };
    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken =
        req.cookies.refreshToken || req.body.refreshToken;
    throwApiError(!incomingRefreshToken, 401, "unauthorized request");

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        const user = await User.findById(decodedToken?._id);
        throwApiError(!user, 401, "Invalid Refresh Token");
        throwApiError(
            incomingRefreshToken !== user.refreshToken,
            401,
            "Refresh Token is expired or used"
        );

        const options = { httpOnly: true, secure: true };
        const { accessToken, refreshToken } =
            await generateAccessAndRefreshToken(user._id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken },
                    "Access Token Refreshed Successfully"
                )
            );
    } catch (error) {
        throw new ApiError(401, error?.message || "invalid refresh token");
    }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    throwApiError(
        oldPassword === newPassword,
        400,
        "Please enter a new password"
    );

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
    throwApiError(!isPasswordCorrect, 400, "old password is incorrect");

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
        .status(200)
        .json(
            new ApiResponse(200, req.user, "Current user fetched successfully")
        );
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email, userName } = req.body;
    throwApiError(
        !fullName && !email && !userName,
        400,
        "Update fields not provided. Invalid request"
    );

    const userExist = await User.findOne({ $and: [{ email }, { userName }] });
    const emailExist = await User.findOne({ email });
    const userNameExist = await User.findOne({ userName });
    throwApiError(userExist, 409, "User already exist");
    throwApiError(emailExist, 409, "email already exist");
    throwApiError(userNameExist, 409, "username already exist");

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        { $set: { fullName, email, userName } },
        { new: true }
    ).select("-password");

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "Account Details updated successfully")
        );
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;
    throwApiError(!avatarLocalPath, 400, "Avatar file is missing");

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    throwApiError(!avatar, 400, "Error while uploading avatar");

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        { $ser: { avatar: avatar?.url } },
        { new: true }
    ).select("-password");

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;
    throwApiError(!coverImageLocalPath, 400, "Cover Image file is missing");

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    throwApiError(!coverImage.url, 400, "Error while uploading cover image");

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        { $ser: { coverImage: coverImage?.url } },
        { new: true }
    ).select("-password");

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Cover Image updated successfully"));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { userName } = req.params;
    throwApiError(!userName?.trim(), 400, "Username is missing");

    const channel = await User.aggregate([
        {
            $match: { userName: userName?.toLowerCase() },
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers",
            },
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribed",
            },
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers",
                },
                channelsSubscribedCount: {
                    $size: "$subscribed",
                },
                isSubscribed: {
                    $cond: {
                        if: { $in: [req.user?._id, "$subscribers.subscriber"] },
                        then: true,
                        else: false,
                    },
                },
            },
        },
        {
            $project: {
                fullName: 1,
                userName: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1,
            },
        },
    ]);
    throwApiError(!channel?.length, 404, "channel not found");

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                channel[0],
                "User Channel details fetched successfully"
            )
        );
});

const getWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id),
            },
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        userName: 1,
                                        avatar: 1,
                                    },
                                },
                            ],
                        },
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: "$owner",
                            },
                        },
                    },
                ],
            },
        },
    ]);

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                user[0].watchHistory,
                "Wtach history fetched successfully"
            )
        );
});

export {
    registerUser,
    loginUser,
    logOutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory,
};
