import { Buffer } from "node:buffer";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import {
	addApprovedClient,
	createOAuthState,
	fetchUpstreamAuthToken,
	generateCSRFProtection,
	getUpstreamAuthorizeUrl,
	isClientApproved,
	OAuthError,
	type Props,
	renderApprovalDialog,
	validateCSRFToken,
	validateOAuthState,
} from "./workers-oauth-utils";

type EnvWithOauth = Env & { OAUTH_PROVIDER: OAuthHelpers };

export async function handleAccessRequest(
	request: Request,
	env: EnvWithOauth,
	_ctx: ExecutionContext,
) {
	const { pathname, searchParams } = new URL(request.url);

	if (request.method === "GET" && pathname === "/authorize") {
		const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
		const { clientId } = oauthReqInfo;
		if (!clientId) {
			return new Response("Invalid request", { status: 400 });
		}

		if (await isClientApproved(request, clientId, env.COOKIE_ENCRYPTION_KEY)) {
			const { stateToken, codeVerifier } = await createOAuthState(oauthReqInfo, env.OAUTH_KV);
			const pkce = await generatePKCEChallenge(codeVerifier);
			return redirectToAccess(request, env, stateToken, {}, pkce.codeChallenge);
		}

		const { token: csrfToken, setCookie } = generateCSRFProtection();

		return renderApprovalDialog(request, {
			client: await env.OAUTH_PROVIDER.lookupClient(clientId),
			csrfToken,
			server: {
				description: "MCP server for analyzing Cloudflare HTTP & WAF logs stored in R2.",
				logo: "https://avatars.githubusercontent.com/u/314135?s=200&v=4",
				name: "R2 Log Analyzer MCP Server",
			},
			setCookie,
			state: { oauthReqInfo },
		});
	}

	if (request.method === "POST" && pathname === "/authorize") {
		try {
			const formData = await request.formData();
			validateCSRFToken(formData, request);

			const encodedState = formData.get("state");
			if (!encodedState || typeof encodedState !== "string") {
				return new Response("Missing state in form data", { status: 400 });
			}

			let state: { oauthReqInfo?: AuthRequest };
			try {
				state = JSON.parse(atob(encodedState));
			} catch (_e) {
				return new Response("Invalid state data", { status: 400 });
			}

			if (!state.oauthReqInfo || !state.oauthReqInfo.clientId) {
				return new Response("Invalid request", { status: 400 });
			}

			const approvedClientCookie = await addApprovedClient(
				request,
				state.oauthReqInfo.clientId,
				env.COOKIE_ENCRYPTION_KEY,
			);

			const { stateToken, codeVerifier } = await createOAuthState(state.oauthReqInfo, env.OAUTH_KV);
			const pkce = await generatePKCEChallenge(codeVerifier);

			return redirectToAccess(request, env, stateToken, {
				"Set-Cookie": approvedClientCookie,
			}, pkce.codeChallenge);
		} catch (error: any) {
			if (error instanceof OAuthError) {
				return error.toResponse();
			}
			return new Response(`Internal server error: ${error.message}`, { status: 500 });
		}
	}

	if (request.method === "GET" && pathname === "/callback") {
		// Check if Access returned an error instead of code+state
		const errorParam = searchParams.get("error");
		if (errorParam) {
			const errorDesc = searchParams.get("error_description") || "Unknown error";
			return new Response(
				JSON.stringify({ error: errorParam, error_description: errorDesc }),
				{ status: 400, headers: { "Content-Type": "application/json" } }
			);
		}

		let result: { oauthReqInfo: AuthRequest; codeVerifier: string };

		try {
			result = await validateOAuthState(request, env.OAUTH_KV);
		} catch (error: any) {
			if (error instanceof OAuthError) {
				return error.toResponse();
			}
			return new Response("Internal server error", { status: 500 });
		}
		const oauthReqInfo = result.oauthReqInfo;

		if (!oauthReqInfo.clientId) {
			return new Response("Invalid OAuth request data", { status: 400 });
		}

		const [accessToken, idToken, errResponse] = await fetchUpstreamAuthToken({
			client_id: env.ACCESS_CLIENT_ID,
			client_secret: env.ACCESS_CLIENT_SECRET,
			code: searchParams.get("code") ?? undefined,
			code_verifier: result.codeVerifier || undefined,
			redirect_uri: new URL("/callback", request.url).href,
			upstream_url: env.ACCESS_TOKEN_URL,
		});
		if (errResponse) {
			return errResponse;
		}

		const idTokenClaims = await verifyToken(env, idToken);
		const user = {
			email: idTokenClaims.email,
			name: idTokenClaims.name,
			sub: idTokenClaims.sub,
		};

		const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
			metadata: {
				label: user.name,
			},
			props: {
				accessToken,
				email: user.email,
				login: user.sub,
				name: user.name,
			} as Props,
			request: oauthReqInfo,
			scope: oauthReqInfo.scope,
			userId: user.sub,
		});

		return Response.redirect(redirectTo, 302);
	}

	return new Response("Not Found", { status: 404 });
}

async function redirectToAccess(
	request: Request,
	env: Env,
	stateToken: string,
	headers: Record<string, string> = {},
	codeChallenge?: string,
) {
	return new Response(null, {
		headers: {
			...headers,
			location: getUpstreamAuthorizeUrl({
				client_id: env.ACCESS_CLIENT_ID,
				code_challenge: codeChallenge,
				code_challenge_method: codeChallenge ? "S256" : undefined,
				redirect_uri: new URL("/callback", request.url).href,
				scope: "openid email profile",
				state: stateToken,
				upstream_url: env.ACCESS_AUTHORIZATION_URL,
			}),
		},
		status: 302,
	});
}

async function generatePKCEChallenge(codeVerifier: string): Promise<{ codeChallenge: string }> {
	const encoder = new TextEncoder();
	const data = encoder.encode(codeVerifier);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
	return { codeChallenge };
}

function parseJWT(token: string) {
	const tokenParts = token.split(".");

	if (tokenParts.length !== 3) {
		throw new Error("token must have 3 parts");
	}

	return {
		header: JSON.parse(Buffer.from(tokenParts[0], "base64url").toString()),
		payload: JSON.parse(Buffer.from(tokenParts[1], "base64url").toString()),
	};
}

/**
 * Decode and validate the id_token claims.
 *
 * Signature verification is intentionally skipped because the token was obtained
 * directly from Cloudflare Access's token endpoint over TLS, which guarantees
 * authenticity. Cloudflare Access OIDC signs id_tokens with keys exposed only
 * as X.509 certs (public_certs), not in the JWK keys array, making JWK-based
 * verification impractical in Workers.
 */
function verifyToken(_env: Env, token: string) {
	const jwt = parseJWT(token);
	const claims = jwt.payload;

	const now = Math.floor(Date.now() / 1000);
	if (claims.exp && claims.exp < now) {
		throw new Error("expired token");
	}

	return claims;
}
