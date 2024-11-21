import {cookies} from "next/headers";
import {GetTokenResponse} from "@/app/auth/auth-types";

export async function isLoggedIn(): Promise<boolean> {
    const accessToken = (await cookies()).get("access_token");

    if (accessToken && accessToken.value && accessToken.value !== "" && accessToken.value !== null) {
        return true;
    }

    const refresh_token = (await cookies()).get("refresh_token");
    return !!(refresh_token && refresh_token.value && refresh_token.value !== "" && refresh_token.value !== null);
}

export async function isAccessTokenPresent(): Promise<boolean> {
    const accessToken = (await cookies()).get("access_token");
    return !!(accessToken && accessToken.value && accessToken.value !== "" && accessToken.value !== null);
}

export async function getAccessTokenFromOauth(code: string): Promise<GetTokenResponse> {
    const requestData = {
        grant_type: "authorization_code",
        client_id: process.env.AUTH_CLIENT_ID!,
        client_secret: process.env.AUTH_CLIENT_SECRET!,
        redirect_uri: process.env.AUTH_REDIRECT_URI!,
        code: code
    }

    return await fetch(`${process.env.GIS_AUTH_ENDPOINT}/oauth/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData)
    }).then(async (response) => {
        if (response.status != 200) {
            console.error(await response.json());
            throw new Error("Error getting access token");
        }
        return await response.json();
    }).catch((error) => {
        console.error(error);
        throw error;
    });
}

export async function refreshAccessToken(): Promise<GetTokenResponse> {
    const refresh_token = (await cookies()).get("refresh_token");
    if (!(refresh_token && refresh_token.value && refresh_token.value !== "" && refresh_token.value !== null)) {
        throw new Error("No refresh token found");
    }

    const requestData = {
        grant_type: "refresh_token",
        client_id: process.env.AUTH_CLIENT_ID!,
        client_secret: process.env.AUTH_CLIENT_SECRET!,
        refresh_token: refresh_token!.value
    }

    return await fetch(`${process.env.GIS_AUTH_ENDPOINT}/oauth/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData)
    }).then(async (response) => {
        if (response.status != 200) {
            console.error(await response.json());
            throw new Error("Error getting access token");
        }
        return await response.json();
    }).catch((error) => {
        console.error(error);
        throw error;
    });
}

export async function getAccessToken(): Promise<string> {
    const accessToken = (await cookies()).get("access_token");
    if (accessToken && accessToken.value && accessToken.value !== "" && accessToken.value !== null) {
        return accessToken.value;
    }
    throw new Error("No access token found");
}
