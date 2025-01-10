import { NextRequest, NextResponse } from "next/server";
import { GetTokenResponse } from "../auth/auth-types";
import { refreshAccessToken } from "../auth/auth-utils";

export async function OPTIONS() {
  // Respond to the preflight request
  const response = new NextResponse(null, { status: 204 });
  response.headers.set("Access-Control-Allow-Origin", "http://localhost:3001");
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Callback-Url"
  );
  response.headers.set("Access-Control-Max-Age", "86400"); // Cache preflight response for 1 day
  return response;
}

export async function GET(request: NextRequest) {
  const externalAppUrl = request.headers.get("X-Callback-Url");

  if (!externalAppUrl) {
    return NextResponse.json(
      { error: "Missing callback URL in request headers." },
      { status: 400 }
    );
  }

  const refreshToken = request.headers.get("Refresh-Token");

  if (refreshToken) {
    try {
      const tokenResponse: GetTokenResponse = await refreshAccessToken(
        refreshToken
      );
      const redirectUrl = new URL(externalAppUrl);
      redirectUrl.searchParams.append(
        "access_token",
        tokenResponse.access_token
      );
      redirectUrl.searchParams.append(
        "refresh_token",
        tokenResponse.refresh_token
      );
      redirectUrl.searchParams.append(
        "expires_in",
        tokenResponse.expires_in.toString()
      );
      if (request.headers.get("X-Requested-With") === "fetch") {
        return NextResponse.json({ redirectUrl: redirectUrl.toString() });
      }
      return NextResponse.redirect(redirectUrl.toString());
    } catch (error) {
      console.error("Error refreshing token:", error);
      return NextResponse.json(
        { error: "Invalid refresh token or session expired." },
        { status: 401 }
      );
    }
  }

  const authUrl = new URL(`${process.env.GIS_AUTH_ENDPOINT}/oauth/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", process.env.AUTH_CLIENT_ID!);
  authUrl.searchParams.set("redirect_uri", process.env.AUTH_REDIRECT_URI!);
  authUrl.searchParams.set("state", externalAppUrl);

  if (request.headers.get("X-Requested-With") === "fetch") {
    return NextResponse.json({ redirectUrl: authUrl.toString() });
  }
  return NextResponse.redirect(authUrl.toString());
}
