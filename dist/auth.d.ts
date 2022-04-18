/// <reference types="node" />
import { IncomingMessage } from "http";
export declare type IdTokenData = {
    sub: string;
    aud: string;
    email_verified: boolean;
    event_id: string;
    token_use: "id";
    auth_time: number;
    iss: string;
    "cognito:username": string;
    exp: number;
    iat: number;
    email: string;
};
export declare type AccessTokenData = {
    sub: string;
    event_id: string;
    token_use: string;
    scope: string;
    auth_time: number;
    iss: string;
    exp: number;
    iat: number;
    jti: string;
    client_id: string;
    username: string;
};
export declare type AuthTokens = {
    accessTokenData: AccessTokenData;
    idTokenData: IdTokenData;
    idToken: string;
    accessToken: string;
} | null;
declare type AWSCognitoPublicPem = string;
declare type AWSCognitoPublicPems = {
    [region: string]: {
        [userPoolId: string]: {
            [kid: string]: AWSCognitoPublicPem;
        };
    };
};
export declare function sync(action: "login" | "logout"): void;
export declare function createGetServerSideAuth({ pems, }: {
    pems: AWSCognitoPublicPems;
}): (req: IncomingMessage) => AuthTokens;
export declare function createUseAuth({ pems }: {
    pems: AWSCognitoPublicPems;
}): (initialAuth: AuthTokens) => AuthTokens;
export declare function useAuthFunctions(): {
    login: () => Promise<import("@aws-amplify/core").ICredentials>;
    logout: () => Promise<void>;
};
export declare function useAuthRedirect(onToken: (token: string | null) => void): null;
export {};
