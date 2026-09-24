export interface SsoPermission {
  path: string;
  method: string;
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  email: string;
  name: string;
  clientId: string;
  roles: string[];
  perm: string;
  iat: number;
  exp: number;
}

export interface SsoSessionData {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  csrfToken: string;
}

export interface SsoUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: SsoPermission[];
}

export interface SsoTransaction {
  state: string;
  codeVerifier: string;
  createdAt: number;
  returnTo?: string;
}

export interface SsoTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}

export interface SsoTokenError {
  error: string;
  error_description?: string;
}

export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  token_endpoint_public: string;
  revocation_endpoint?: string;
  permissions_endpoint?: string;
  introspection_endpoint?: string;
  jwks_uri: string;
}

export interface SsoMe extends SsoUser {
  csrfToken: string;
  csrfCookieName: string;
}
