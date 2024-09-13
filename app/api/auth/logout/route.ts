import connect from "@/lib/db";
import { NextResponse } from "next/server";

export const POST = async () => {
    await connect();

    // Create a response object
    const response = NextResponse.json({ message: "Logged out successfully" });

    // Clear the cookie
    response.cookies.set("jwt-linkedin", "", {
        httpOnly: true,
        expires: new Date(0), // Set expiry date to past to clear the cookie
        path: "/", // Optional: specify path if needed
    });

    // Return the response
    return response;
};
