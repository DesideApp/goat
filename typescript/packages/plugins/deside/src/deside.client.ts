import { randomUUID } from "node:crypto";
import { SolanaWalletClient } from "@goat-sdk/wallet-solana";
import bs58 from "bs58";
import {
    GetUserInfoParameters,
    ListConversationsParameters,
    MarkDmReadParameters,
    NoParameters,
    ReadDmsParameters,
    SearchAgentsParameters,
    SendDmParameters,
} from "./parameters";
import { DesideOAuthTokens, DesidePluginOptions, DesideSignatureEncoding, DesideTransportError } from "./types";

type JsonObject = Record<string, unknown>;

type HttpJsonResponse = {
    status: number;
    headers: Headers;
    data: unknown;
};

type McpRpcResponse = {
    status: number;
    sessionId: string | null;
    jsonRpc: JsonObject | null;
    raw: unknown;
};

type ParsedToolResult =
    | {
          ok: true;
          data: unknown;
      }
    | {
          ok: false;
          error: JsonObject;
      };

export class DesideClient {
    private readonly baseUrl: string;
    private readonly mcpPath: string;
    private readonly oauthClientName: string;
    private readonly oauthRedirectUri: string;
    private readonly oauthScope: string;
    private readonly clientVersion: string;
    private readonly signatureEncoding: DesideSignatureEncoding;

    private sessionId: string | null = null;
    private sessionPromise: Promise<string> | null = null;
    private clientId: string | null = null;
    private readonly authStateByWallet = new Map<string, DesideOAuthTokens>();
    private readonly authPromiseByWallet = new Map<string, Promise<DesideOAuthTokens>>();

    constructor(options: DesidePluginOptions) {
        this.baseUrl = (options.baseUrl || "https://mcp.deside.io").replace(/\/+$/, "");
        this.mcpPath = options.mcpPath || "/mcp";
        this.oauthClientName = options.oauthClientName || "goat-plugin-deside";
        this.oauthRedirectUri = options.oauthRedirectUri;
        this.oauthScope = options.oauthScope || "dm:read dm:write";
        this.clientVersion = options.clientVersion || "0.1.0";
        this.signatureEncoding = options.signatureEncoding || "auto";
    }

    async sendDm(walletClient: SolanaWalletClient, parameters: SendDmParameters) {
        return this.callTool(walletClient, "send_dm", this.toJsonObject(parameters));
    }

    async readDms(walletClient: SolanaWalletClient, parameters: ReadDmsParameters) {
        return this.callTool(walletClient, "read_dms", this.toJsonObject(parameters));
    }

    async markDmRead(walletClient: SolanaWalletClient, parameters: MarkDmReadParameters) {
        return this.callTool(walletClient, "mark_dm_read", this.toJsonObject(parameters));
    }

    async listConversations(walletClient: SolanaWalletClient, parameters: ListConversationsParameters) {
        return this.callTool(walletClient, "list_conversations", this.toJsonObject(parameters));
    }

    async getUserInfo(walletClient: SolanaWalletClient, parameters: GetUserInfoParameters) {
        return this.callTool(walletClient, "get_user_info", this.toJsonObject(parameters));
    }

    async getMyIdentity(walletClient: SolanaWalletClient, _parameters: NoParameters) {
        return this.callTool(walletClient, "get_my_identity", {});
    }

    async searchAgents(walletClient: SolanaWalletClient, parameters: SearchAgentsParameters) {
        return this.callTool(walletClient, "search_agents", this.toJsonObject(parameters));
    }

    private async callTool(
        walletClient: SolanaWalletClient,
        name: string,
        args: JsonObject,
        retry = true,
    ): Promise<unknown> {
        const sessionId = await this.ensureSession();
        const accessToken = await this.ensureAccessToken(walletClient);
        const rpc = await this.mcpRpc({
            sessionId,
            bearerToken: accessToken,
            id: Date.now(),
            method: "tools/call",
            params: { name, arguments: args },
        });

        if (this.isSessionExpiredTransportError(rpc.raw) && retry) {
            this.sessionId = null;
            return this.callTool(walletClient, name, args, false);
        }

        const result = this.parseToolResult(rpc.jsonRpc);
        if (result.ok) {
            return result.data;
        }

        if (this.isAuthRequiredError(result.error) && retry) {
            await this.refreshOrReauthenticate(walletClient);
            return this.callTool(walletClient, name, args, false);
        }

        throw new Error(`Deside tool ${name} failed: ${JSON.stringify(result.error)}`);
    }

    private async ensureSession(): Promise<string> {
        if (this.sessionId) {
            return this.sessionId;
        }
        if (this.sessionPromise) {
            return this.sessionPromise;
        }

        this.sessionPromise = this.initializeSession();
        try {
            this.sessionId = await this.sessionPromise;
            return this.sessionId;
        } finally {
            this.sessionPromise = null;
        }
    }

    private async initializeSession(): Promise<string> {
        const initialize = await this.mcpRpc({
            id: 1,
            method: "initialize",
            params: {
                protocolVersion: "2025-11-25",
                capabilities: {},
                clientInfo: {
                    name: this.oauthClientName,
                    version: this.clientVersion,
                },
            },
        });

        if (!initialize.sessionId) {
            throw new Error(`Deside initialize failed: missing mcp-session-id. Raw=${JSON.stringify(initialize.raw)}`);
        }

        await this.mcpRpc({
            sessionId: initialize.sessionId,
            method: "notifications/initialized",
        });

        return initialize.sessionId;
    }

    private async ensureAccessToken(walletClient: SolanaWalletClient): Promise<string> {
        const wallet = walletClient.getAddress();
        const current = this.authStateByWallet.get(wallet);
        if (current && current.expiresAt > Date.now() + 60_000) {
            return current.accessToken;
        }
        if (current?.refreshToken) {
            const refreshed = await this.refreshAccessToken(current.refreshToken);
            this.authStateByWallet.set(wallet, refreshed);
            return refreshed.accessToken;
        }

        return this.authenticate(walletClient).then((tokens) => tokens.accessToken);
    }

    private async authenticate(walletClient: SolanaWalletClient): Promise<DesideOAuthTokens> {
        const wallet = walletClient.getAddress();
        const existing = this.authPromiseByWallet.get(wallet);
        if (existing) {
            return existing;
        }

        const promise = this.authenticateInner(walletClient);
        this.authPromiseByWallet.set(wallet, promise);

        try {
            const tokens = await promise;
            this.authStateByWallet.set(wallet, tokens);
            return tokens;
        } finally {
            this.authPromiseByWallet.delete(wallet);
        }
    }

    private async authenticateInner(walletClient: SolanaWalletClient): Promise<DesideOAuthTokens> {
        if (!this.oauthRedirectUri) {
            throw new Error("Deside OAuth requires oauthRedirectUri in plugin options");
        }

        await this.ensureSession();
        const clientId = await this.ensureOAuthClientId();
        const state = randomUUID();
        const verifier = `goat-deside-${randomUUID()}`;
        const challenge = await this.buildPkceChallenge(verifier);

        const authorizeUrl = new URL("/oauth/authorize", this.baseUrl);
        authorizeUrl.searchParams.set("client_id", clientId);
        authorizeUrl.searchParams.set("redirect_uri", this.oauthRedirectUri);
        authorizeUrl.searchParams.set("response_type", "code");
        authorizeUrl.searchParams.set("code_challenge", challenge);
        authorizeUrl.searchParams.set("code_challenge_method", "S256");
        authorizeUrl.searchParams.set("scope", this.oauthScope);
        authorizeUrl.searchParams.set("state", state);

        const authorizeRes = await this.httpJson(authorizeUrl.toString(), {
            method: "GET",
            redirect: "manual",
        });
        const challengeUrl = authorizeRes.headers.get("location");
        if (authorizeRes.status !== 302 || !challengeUrl) {
            throw new Error(`Deside OAuth authorize failed: ${JSON.stringify(authorizeRes.data)}`);
        }

        const walletChallengeGet = await this.httpJson(challengeUrl, {
            method: "GET",
            redirect: "manual",
        });
        const challengeData = this.asObject(walletChallengeGet.data);
        const nonce = this.readString(challengeData, "nonce");
        const domain = this.readString(challengeData, "domain");
        const challengeState = this.readString(challengeData, "state") || state;

        if (walletChallengeGet.status !== 200 || !nonce || !domain) {
            throw new Error(`Deside wallet challenge bootstrap failed: ${JSON.stringify(walletChallengeGet.data)}`);
        }

        const message = `Domain: ${domain}\nNonce: ${nonce}`;
        const signed = await walletClient.signMessage(message);
        const signature = this.normalizeSignature(signed.signature);

        const challengePost = await this.httpJson(`${this.baseUrl}/oauth/wallet-challenge`, {
            method: "POST",
            redirect: "manual",
            body: {
                wallet: walletClient.getAddress(),
                signature,
                message,
                state: challengeState,
            },
        });
        const codeRedirect = challengePost.headers.get("location");
        if (challengePost.status !== 302 || !codeRedirect) {
            throw new Error(`Deside wallet challenge submit failed: ${JSON.stringify(challengePost.data)}`);
        }

        const code = new URL(codeRedirect).searchParams.get("code");
        if (!code) {
            throw new Error(`Deside OAuth returned no authorization code: ${codeRedirect}`);
        }

        return this.exchangeAuthorizationCode({
            clientId,
            code,
            codeVerifier: verifier,
        });
    }

    private async refreshOrReauthenticate(walletClient: SolanaWalletClient) {
        const wallet = walletClient.getAddress();
        const current = this.authStateByWallet.get(wallet);
        if (current?.refreshToken) {
            try {
                const refreshed = await this.refreshAccessToken(current.refreshToken);
                this.authStateByWallet.set(wallet, refreshed);
                return;
            } catch {
                this.authStateByWallet.delete(wallet);
            }
        }

        const tokens = await this.authenticate(walletClient);
        this.authStateByWallet.set(wallet, tokens);
    }

    private async ensureOAuthClientId(): Promise<string> {
        if (this.clientId) {
            return this.clientId;
        }

        const registerRes = await this.httpJson(`${this.baseUrl}/oauth/register`, {
            method: "POST",
            body: {
                client_name: this.oauthClientName,
                redirect_uris: [this.oauthRedirectUri],
                grant_types: ["authorization_code"],
                token_endpoint_auth_method: "none",
                scope: this.oauthScope,
            },
        });

        const payload = this.asObject(registerRes.data);
        const clientId = this.readString(payload, "client_id");
        if (registerRes.status !== 200 || !clientId) {
            throw new Error(`Deside OAuth client registration failed: ${JSON.stringify(registerRes.data)}`);
        }

        this.clientId = clientId;
        return clientId;
    }

    private async exchangeAuthorizationCode(input: {
        clientId: string;
        code: string;
        codeVerifier: string;
    }): Promise<DesideOAuthTokens> {
        const tokenRes = await this.httpJson(`${this.baseUrl}/oauth/token`, {
            method: "POST",
            body: {
                grant_type: "authorization_code",
                code: input.code,
                client_id: input.clientId,
                redirect_uri: this.oauthRedirectUri,
                code_verifier: input.codeVerifier,
            },
        });
        return this.parseTokenResponse(tokenRes, "authorization_code");
    }

    private async refreshAccessToken(refreshToken: string): Promise<DesideOAuthTokens> {
        const clientId = await this.ensureOAuthClientId();
        const tokenRes = await this.httpJson(`${this.baseUrl}/oauth/token`, {
            method: "POST",
            body: {
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: clientId,
            },
        });
        return this.parseTokenResponse(tokenRes, "refresh_token");
    }

    private parseTokenResponse(response: HttpJsonResponse, grantType: string): DesideOAuthTokens {
        const payload = this.asObject(response.data);
        const accessToken = this.readString(payload, "access_token");
        const refreshToken = this.readString(payload, "refresh_token");
        const expiresIn = this.readNumber(payload, "expires_in");

        if (response.status !== 200 || !accessToken || !expiresIn) {
            throw new Error(`Deside OAuth ${grantType} failed: ${JSON.stringify(response.data)}`);
        }

        return {
            accessToken,
            refreshToken,
            expiresAt: Date.now() + expiresIn * 1000,
        };
    }

    private async mcpRpc(input: {
        sessionId?: string | null;
        bearerToken?: string | null;
        method: string;
        params?: JsonObject;
        id?: number;
    }): Promise<McpRpcResponse> {
        const payload: JsonObject = {
            jsonrpc: "2.0",
            method: input.method,
        };
        if (input.params !== undefined) {
            payload.params = input.params;
        }
        if (input.id !== undefined) {
            payload.id = input.id;
        }

        const response = await this.httpJson(`${this.baseUrl}${this.mcpPath}`, {
            method: "POST",
            headers: {
                accept: "application/json, text/event-stream",
                ...(input.sessionId ? { "mcp-session-id": input.sessionId } : {}),
                ...(input.bearerToken ? { authorization: `Bearer ${input.bearerToken}` } : {}),
            },
            body: payload,
        });

        return {
            status: response.status,
            sessionId: response.headers.get("mcp-session-id") || input.sessionId || null,
            jsonRpc: this.parseMcpEnvelope(response.data),
            raw: response.data,
        };
    }

    private async httpJson(
        url: string,
        input: {
            method?: string;
            headers?: Record<string, string>;
            body?: JsonObject;
            redirect?: RequestRedirect;
        } = {},
    ): Promise<HttpJsonResponse> {
        const response = await fetch(url, {
            method: input.method || "GET",
            headers: {
                "content-type": "application/json",
                ...input.headers,
            },
            body: input.body ? JSON.stringify(input.body) : undefined,
            redirect: input.redirect || "follow",
        });

        const text = await response.text();
        let data: unknown = null;

        try {
            data = text ? JSON.parse(text) : null;
        } catch {
            data = text;
        }

        return {
            status: response.status,
            headers: response.headers,
            data,
        };
    }

    private parseMcpEnvelope(payload: unknown): JsonObject | null {
        if (payload && typeof payload === "object") {
            return payload as JsonObject;
        }
        if (typeof payload !== "string" || !payload.startsWith("event: message")) {
            return null;
        }

        const marker = "data: ";
        const index = payload.indexOf(marker);
        if (index < 0) {
            return null;
        }

        try {
            return JSON.parse(payload.slice(index + marker.length).trim()) as JsonObject;
        } catch {
            return null;
        }
    }

    private parseToolResult(jsonRpc: JsonObject | null): ParsedToolResult {
        const result = jsonRpc?.result;
        if (!result || typeof result !== "object") {
            return {
                ok: false,
                error: this.asObject(jsonRpc?.error) || { message: "missing_result" },
            };
        }

        const resultObject = result as JsonObject;
        if (resultObject.isError) {
            const content = Array.isArray(resultObject.content) ? resultObject.content : [];
            const textPart = content.find((part) => {
                if (!part || typeof part !== "object") {
                    return false;
                }
                const entry = part as JsonObject;
                return entry.type === "text" && typeof entry.text === "string";
            }) as JsonObject | undefined;

            if (typeof textPart?.text === "string") {
                try {
                    return {
                        ok: false,
                        error: JSON.parse(textPart.text) as JsonObject,
                    };
                } catch {
                    return {
                        ok: false,
                        error: { message: textPart.text },
                    };
                }
            }

            return {
                ok: false,
                error: { message: "tool_error_without_payload" },
            };
        }

        const structuredContent = resultObject.structuredContent;
        if (structuredContent && typeof structuredContent === "object") {
            return { ok: true, data: structuredContent };
        }

        return { ok: true, data: resultObject };
    }

    private isAuthRequiredError(error: JsonObject): boolean {
        return error.error === "AUTH_REQUIRED" || error.code === "AUTH_REQUIRED" || error.status === 401;
    }

    private isSessionExpiredTransportError(raw: unknown): boolean {
        const payload = this.asObject(raw) as DesideTransportError | null;
        return payload?.error === "session_not_found" || payload?.status === 404;
    }

    private async buildPkceChallenge(verifier: string): Promise<string> {
        const hash = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
        return Buffer.from(hash).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    private normalizeSignature(signature: string): string {
        switch (this.signatureEncoding) {
            case "base58":
                return signature;
            case "hex":
                return bs58.encode(Buffer.from(signature, "hex"));
            case "base64":
                return bs58.encode(Buffer.from(signature, "base64"));
            case "auto":
                return this.normalizeSignatureAuto(signature);
        }
    }

    private normalizeSignatureAuto(signature: string): string {
        if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(signature)) {
            return signature;
        }
        if (/^[0-9a-fA-F]+$/.test(signature) && signature.length % 2 === 0) {
            return bs58.encode(Buffer.from(signature, "hex"));
        }
        if (/^[A-Za-z0-9+/=]+$/.test(signature)) {
            return bs58.encode(Buffer.from(signature, "base64"));
        }
        return signature;
    }

    private asObject(value: unknown): JsonObject | null {
        if (value && typeof value === "object" && !Array.isArray(value)) {
            return value as JsonObject;
        }
        return null;
    }

    private readString(value: JsonObject | null, key: string): string | null {
        const candidate = value?.[key];
        return typeof candidate === "string" && candidate.length > 0 ? candidate : null;
    }

    private readNumber(value: JsonObject | null, key: string): number | null {
        const candidate = value?.[key];
        return typeof candidate === "number" && Number.isFinite(candidate) ? candidate : null;
    }

    private toJsonObject<T>(value: T): JsonObject {
        return value as JsonObject;
    }
}
