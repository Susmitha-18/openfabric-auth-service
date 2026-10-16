import "dotenv/config";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type RemoteJWKSet,
} from "jose";

export interface AuthenticatedUser {
  userId: string;
  subject: string;
  claims: JWTPayload;
}

// JWKS client is created lazily on first call so that the module can be
// imported in test environments that do not have Cognito credentials.
let _jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let _issuer: string | null = null;
let _clientId: string | null = null;

function getConfig(): {
  jwks: ReturnType<typeof createRemoteJWKSet>;
  issuer: string;
  clientId: string;
} {
  if (_jwks && _issuer && _clientId) {
    return { jwks: _jwks, issuer: _issuer, clientId: _clientId };
  }

  const region = process.env.AWS_REGION;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const clientId = process.env.COGNITO_CLIENT_ID;

  if (!region || !userPoolId || !clientId) {
    throw new Error(
      "Missing AWS_REGION, COGNITO_USER_POOL_ID, or COGNITO_CLIENT_ID in .env"
    );
  }

  // Only accept tokens issued by this Cognito User Pool.
  _issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  _clientId = clientId;

  // Cognito publishes public signing keys so we can verify JWT signatures.
  const jwksUrl = new URL(`${_issuer}/.well-known/jwks.json`);
  _jwks = createRemoteJWKSet(jwksUrl, {
    timeoutDuration: 10_000,
  });

  return { jwks: _jwks, issuer: _issuer, clientId: _clientId };
}

// Verify the signature and standard JWT claims, then validate Cognito claims.
export async function validateAccessToken(
  accessToken: string
): Promise<AuthenticatedUser> {
  if (!accessToken || typeof accessToken !== "string") {
    throw new Error("Access token is required");
  }

  const { jwks, issuer, clientId } = getConfig();

  const { payload } = await jwtVerify(accessToken, jwks, {
    issuer,
    algorithms: ["RS256"],
  });

  // Cognito access tokens use client_id rather than the ID-token aud claim.
  if (payload.token_use !== "access") {
    throw new Error("Token must be a Cognito access token");
  }

  if (payload.client_id !== clientId) {
    throw new Error("Token was issued to a different app client");
  }

  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new Error("Token does not contain a valid user subject");
  }

  // Cognito commonly includes username in its access-token claims.
  // Fall back to sub, the stable Cognito user identifier.
  const username = payload.username;

  const userId =
    typeof username === "string" && username.length > 0
      ? username
      : payload.sub;

  return {
    userId,
    subject: payload.sub,
    claims: payload,
  };
}
