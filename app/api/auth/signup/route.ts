import connect from "@/lib/db";
import User from "@/models/User";
import bcrypt from "bcryptjs";
import { NextRequest, NextResponse } from "next/server";
import jwt from "jsonwebtoken";

export const POST = async (req: NextRequest) => {
    try {
        const body = await req.json(); // Parse the request body
        const { name, username, email, password } = body;
        await connect();

        // Check if all required fields are present
        if (!name || !username || !email || !password) {
            return NextResponse.json({
                success: false,
                error: true,
                message: "All fields are required"
            });
        }

        // Check if email already exists
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return NextResponse.json({
                success: false,
                message: "Email already exists"
            });
        }

        // Check if username already exists
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return NextResponse.json({
                success: false,
                message: "Username already exists"
            });
        }

        // Check if password is long enough
        if (password.length < 6) {
            return NextResponse.json({
                success: false,
                message: "Password must be at least 6 characters"
            });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            username,
        });

        await user.save();

        // Create JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET!, { expiresIn: "3d" });

        // Create a response and set the cookie
        const response = NextResponse.json({
            success: true,
            message: "Signup successful"
        });

        // Set the cookie using cookies.set
        response.cookies.set("jwt-linkedin", token, {
            httpOnly: true, // Prevent XSS
            maxAge: 3 * 24 * 60 * 60, // 3 days in seconds
            sameSite: "strict", // Prevent CSRF
            secure: process.env.NODE_ENV === "production", // Only use in production for HTTPS
        });

        return response;

    } catch (error) {
        console.error("Error during signup:", error);
        return NextResponse.json({
            success: false,
            error: true,
            message: "Internal server error"
        });
    }
};
