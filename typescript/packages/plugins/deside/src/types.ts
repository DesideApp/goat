export type DesideSignatureEncoding = "auto" | "base58" | "hex" | "base64";

export type DesidePluginOptions = {
    baseUrl?: string;
    mcpPath?: string;
    oauthClientName?: string;
    oauthRedirectUri: string;
    oauthScope?: string;
    clientVersion?: string;
    signatureEncoding?: DesideSignatureEncoding;
};

export type DesideTransportError = {
    error?: string;
    message?: string;
    status?: number;
};

export type DesideOAuthTokens = {
    accessToken: string;
    refreshToken: string | null;
    expiresAt: number;
};
