import { NextRequest, NextResponse } from "next/server";
import jwt, { JwtPayload } from "jsonwebtoken";
import connect from "@/lib/db"; // Ensure the database is connected
import User from "@/models/User";

// Define the expected JWT payload type
interface DecodedToken extends JwtPayload {
	userId: string;
}

export const protectRoute = async (req: NextRequest) => {
	try {
		// Connect to the database
		await connect();

		// Extract token from cookies
		const token = req.cookies.get("jwt-linkedin")?.value;

		if (!token) {
			return NextResponse.json({ message: "Unauthorized - No Token Provided" }, { status: 401 });
		}

		// Verify the token and assert the type
		const decoded = jwt.verify(token, process.env.JWT_SECRET!) as DecodedToken;

		if (!decoded || !decoded.userId) {
			return NextResponse.json({ message: "Unauthorized - Invalid Token" }, { status: 401 });
		}

		// Find the user based on the decoded token's userId
		const user = await User.findById(decoded.userId).select("-password");

		if (!user) {
			return NextResponse.json({ message: "User not found" }, { status: 401 });
		}

		// Return the user object to the route handler
		return user;
	} catch (error) {
		console.error("Error in protectRoute middleware:", error);
		return NextResponse.json({ message: "Internal server error" }, { status: 500 });
	}
};
