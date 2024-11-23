import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import {
  refreshAccessToken,
} from "@/app/auth/auth-utils";
import { GetTokenResponse } from "@/app/auth/auth-types";

export async function middleware(request: NextRequest) {
  const lastUrl = `${process.env.BASE_URL}${request.nextUrl.pathname}`;

  const refreshToken = request.headers.get("Refresh-Token");

  if (refreshToken) {
    try {
      const tokenResponse: GetTokenResponse = await refreshAccessToken(
        refreshToken
      );
      return NextResponse.json({
        access_token: tokenResponse.access_token,
        refresh_token: tokenResponse.refresh_token,
        expires_in: tokenResponse.expires_in,
      });
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
  authUrl.searchParams.set("state", "");

  const redirectResponse = NextResponse.redirect(authUrl.toString());

  redirectResponse.headers.set("X-Requested-Url", lastUrl);

  return redirectResponse;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - auth (authentication routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    "/((?!api|auth|_next/static|_next/image|favicon.ico).*)",
  ],
};
