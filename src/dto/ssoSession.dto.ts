/** Permissao de rota, como vem no access token emitido pelo SSO. */
export interface SsoPermission {
  path: string;
  method: string;
}

/** Claims do access token emitido pelo SSO. */
export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  email: string;
  name: string;
  clientId: string;
  /** RFC 9068 secao 2.2.3.1. O token leva o papel, nao a lista de rotas. */
  roles: string[];
  /** Impressao digital do conjunto de permissoes. Chave de cache. */
  perm: string;
  iat: number;
  exp: number;
}

/**
 * Conteudo do cookie de sessao.
 *
 * RFC 10017 secao 6.1.2.3 permite sessao client-side, e a secao 6.1.3.2 diz
 * que nesse caso o conteudo do cookie SHOULD ser cifrado. E o que fazemos: o
 * navegador recebe um blob opaco, e nenhum token trafega em claro nem fica
 * acessivel a JavaScript.
 */
export interface SsoSessionData {
  accessToken: string;
  refreshToken: string;
  /** Epoch em segundos. Copiado do `exp` para evitar decodificar a cada request. */
  expiresAt: number;
  /**
   * Token anti-CSRF desta sessao. Fica aqui, dentro do cifrado, porque esta
   * e a copia contra a qual o header enviado pelo front e comparado.
   * Sobrevive a renovacao do access token: trocar a cada refresh silencioso
   * invalidaria a copia que o front ja tem em mao.
   */
  csrfToken: string;
}

/** Identidade resolvida, anexada ao request para uso da aplicacao. */
export interface SsoUser {
  id: string;
  email: string;
  name: string;
  /** Como veio no token. */
  roles: string[];
  /** Resolvidas a partir dos papeis, com cache. */
  permissions: SsoPermission[];
}

/** Transacao de login, guardada no cookie enquanto o usuario esta no SSO. */
export interface SsoTransaction {
  state: string;
  codeVerifier: string;
  /** Epoch em segundos. */
  createdAt: number;
  /** Para onde voltar depois do login, se diferente do padrao. */
  returnTo?: string;
}

/** Resposta do token endpoint (RFC 6749 secao 5.1). */
export interface SsoTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}

/** Erro do token endpoint (RFC 6749 secao 5.2). */
export interface SsoTokenError {
  error: string;
  error_description?: string;
}

/**
 * Metadados do AS (RFC 8414 secao 2), lidos do discovery.
 *
 * `token_endpoint` e `jwks_uri` ja vem reescritos para o endereco de rede,
 * porque quem os chama e este processo. `token_endpoint_public` guarda a
 * forma original, que e o que vai na claim `aud` da asserção de cliente: o
 * SSO valida a audiencia contra a propria URL publica, nao contra o nome de
 * servico interno.
 */
export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  token_endpoint_public: string;
  /** RFC 7009. Ausente quando o servidor nao anuncia revogacao. */
  revocation_endpoint?: string;
  /** Extensao propria do SSO: resolve `roles` em permissoes. */
  permissions_endpoint?: string;
  /** RFC 7662. Ausente em SSO que ainda nao introspecta: a checagem desliga. */
  introspection_endpoint?: string;
  jwks_uri: string;
}

/** Resposta de `GET /auth/me`: identidade mais o token anti-CSRF. */
export interface SsoMe extends SsoUser {
  /**
   * O front devolve este valor no header `X-CSRF-Token` nas requisicoes que
   * mudam estado. Tambem chega pelo cookie legivel `app_csrf`; os dois
   * caminhos existem para o front escolher o que preferir.
   */
  csrfToken: string;
  /**
   * Nome real do cookie legivel que carrega o mesmo valor. Varia por
   * aplicacao, entao o front le daqui em vez de fixar a string.
   */
  csrfCookieName: string;
}
