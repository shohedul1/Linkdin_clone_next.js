import connect from "@/lib/db";
import User from "@/models/User";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { NextRequest, NextResponse } from "next/server";

export const POST = async (req: NextRequest) => {
    try {
        const body = await req.json(); // Parse the request body
        const { username, password } = body;
        connect();
        // Check if user exists
        const user = await User.findOne({ username });
        if (!user) {
            return NextResponse.json({
                success: false,
                message: "Invalid credentials"

            })
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return NextResponse.json({
                success: false,
                message: "Invalid credentials"
            })
        }

        // Create and send token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET!, { expiresIn: "3d" });
        // Create a response and set the cookie
        const response = NextResponse.json({
            success: true,
            message: "login successful"
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
        console.log(error);

    }
};