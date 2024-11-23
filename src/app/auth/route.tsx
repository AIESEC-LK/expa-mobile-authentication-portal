import {NextRequest, NextResponse} from "next/server";
import {cookies} from "next/headers";
import {getAccessTokenFromOauth} from "@/app/auth/auth-utils";
import {GetTokenResponse} from "@/app/auth/auth-types";

export async function GET(request: NextRequest) {
    const code: string | null = request.nextUrl.searchParams.get('code');
    if (!code) {
        return NextResponse.json(
            { error: 'Authorization code is required' },
            { status: 400 }
        );
    }

    try {
        const authResponse: GetTokenResponse = await getAccessTokenFromOauth(code);

        const redirect_uri = (await cookies()).get('redirect_uri')?.value ?? process.env.NEXT_PUBLIC_BASE_URL;

        console.log('Redirect URI:', redirect_uri);

        return NextResponse.json({
            access_token: authResponse.access_token,
            refresh_token: authResponse.refresh_token,
            expires_in: authResponse.expires_in,
            redirect_uri,
        });
    } catch (error) {
        console.error('Error fetching tokens:', error);
        return NextResponse.json(
            { error: 'Failed to exchange authorization code for tokens' },
            { status: 500 }
        );
    }
}