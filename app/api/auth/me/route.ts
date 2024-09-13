
import connect from "@/lib/db";
import { protectRoute } from "@/middleware";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
    connect()
    // Call the protectRoute function to validate the user
    const user = await protectRoute(req);

    // If protectRoute returns a response (e.g., error), return it
    if (user instanceof NextResponse) {
        return user;
    }

    // Your protected logic here
    return NextResponse.json({
        message: "This is a protected route",
        user, // Include user data in the response
    });
};
