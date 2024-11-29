import { NextRequest, NextResponse } from "next/server";
import { getAccessTokenFromOauth } from "@/app/auth/auth-utils";
import { GetTokenResponse } from "@/app/auth/auth-types";

export async function GET(request: NextRequest) {
  const { code, state } = Object.fromEntries(request.nextUrl.searchParams);
  if (!code) {
    return NextResponse.json(
      { error: "Authorization code is required" },
      { status: 400 }
    );
  }

  if (!state) {
    return NextResponse.json({ error: "State is required" }, { status: 400 });
  }

  try {
    const authResponse: GetTokenResponse = await getAccessTokenFromOauth(code);

    const externalUrl = new URL(state);

    externalUrl.searchParams.set("access_token", authResponse.access_token);
    externalUrl.searchParams.set("refresh_token", authResponse.refresh_token);
    externalUrl.searchParams.set("expires_in", authResponse.expires_in.toString());

    return NextResponse.redirect(externalUrl.toString());
  } catch (error) {
    console.error("Error fetching tokens:", error);
    return NextResponse.json(
      { error: "Failed to exchange authorization code for tokens" },
      { status: 500 }
    );
  }
}
