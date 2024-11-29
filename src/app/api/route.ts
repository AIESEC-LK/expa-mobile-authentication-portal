import { NextRequest, NextResponse } from "next/server";
import { GetTokenResponse } from "../auth/auth-types";
import { refreshAccessToken } from "../auth/auth-utils";

export async function GET(request: NextRequest){

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
      const response = await fetch(externalAppUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          access_token: tokenResponse.access_token,
          refresh_token: tokenResponse.refresh_token,
          expires_in: tokenResponse.expires_in,
        }),
      });
      if (!response.ok) {
        console.error("Failed to notify external application:", await response.text());
        return NextResponse.json(
          { error: "Failed to notify external application." },
          { status: 502 }
        );
      }
      return NextResponse.json({ success: true });
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