/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    ApolloClient,
    DocumentNode,
    InMemoryCache,
    NormalizedCacheObject,
    OperationVariables,
    TypedDocumentNode
} from "@apollo/client";
import {getAccessToken} from "@/app/auth/auth-utils";

const APOLLO_CLIENTS = new Map();

export async function runQuery(query: DocumentNode | TypedDocumentNode<any, OperationVariables>, variables?: any) {
    // console.info("Running query: ", query.loc?.source.body.toString());
    // console.info("Access token: ", getAccessToken());

    let client: ApolloClient<NormalizedCacheObject>;
    if (APOLLO_CLIENTS.has(getAccessToken())) {
        client = APOLLO_CLIENTS.get(getAccessToken());
    } else {
        client = new ApolloClient({
            uri: process.env.GIS_API_ENDPOINT,
            cache: new InMemoryCache(),
            headers: {
                authorization: await getAccessToken(),
            },
        });
        APOLLO_CLIENTS.set(getAccessToken(), client);
    }

    const cachedData = client.readQuery({
        query: query,
        variables: variables,
    });

    if (cachedData) return cachedData;

    const {data, errors} = await client.query({
        query, variables
    });

    if (errors) {
        console.error(errors.toString());
        throw new Error(errors.toString());
    }

    // console.info(data);
    return data;
}

export async function runQueryWithAccessToken(accessToken: string,
                                              query: DocumentNode | TypedDocumentNode<any, OperationVariables>,
                                              variables?: any) {
    const client = new ApolloClient({
        uri: process.env.GIS_API_ENDPOINT,
        cache: new InMemoryCache(),
        headers: {
            authorization: accessToken,
        },
    });

    const {data, errors} = await client.query({
        query, variables
    });

    if (errors) {
        throw new Error(errors.toString());
    }

    return data;
}
