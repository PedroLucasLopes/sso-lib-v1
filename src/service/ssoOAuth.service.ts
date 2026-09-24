import {
  BadGatewayException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { SsoCookieService } from '../cookie/cookie.service';
import {
  SSO_CLIENT_OPTIONS,
  SSO_TX_COOKIE,
  TX_COOKIE_TTL_SECONDS,
} from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type {
  SsoSessionData,
  SsoTokenError,
  SsoTokenResponse,
  SsoTransaction,
} from '../dto/ssoSession.dto';
import { SsoLoginFailedException } from '../error/loginFailed.exception';
import type { SsoLoginErrorCode } from '../error/loginFailed.exception';
import { isPageNavigation } from '../error/pageNavigation';
import {
  CLIENT_ASSERTION_TYPE,
  SsoClientAssertionService,
} from './clientAssertion.service';
import { SsoDiscoveryService } from './discovery.service';
import { SsoSessionService } from './ssoSession.service';

const RENEWAL_REUSE_MS = 30_000;

@Injectable()
export class SsoOAuthService {
  private readonly logger = new Logger(SsoOAuthService.name);
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly postLoginRedirect: string;
  private readonly ownOrigin: string;
  private readonly appBaseUrl: string;
  private readonly refreshSkewSeconds: number;
  private readonly loginErrorRedirect: URL | null;

  private readonly renewals = new Map<
    string,
    { promise: Promise<SsoTokenResponse>; settledAt?: number }
  >();

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private cookies: SsoCookieService,
    private discovery: SsoDiscoveryService,
    private assertions: SsoClientAssertionService,
    private sessions: SsoSessionService,
  ) {
    const appBaseUrl = options.appBaseUrl.replace(/\/+$/, '');

    this.issuer = options.issuer.replace(/\/+$/, '');
    this.clientId = options.clientId;
    this.redirectUri = `${appBaseUrl}/auth/callback`;
    this.postLoginRedirect = options.postLoginRedirect ?? '/';
    this.ownOrigin = new URL(appBaseUrl).origin;
    this.appBaseUrl = appBaseUrl;
    this.refreshSkewSeconds = options.refreshSkewSeconds ?? 60;
    this.loginErrorRedirect = options.loginErrorRedirect
      ? new URL(options.loginErrorRedirect, this.ownOrigin)
      : null;
  }

  async beginLogin(res: Response, returnTo?: string): Promise<void> {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier, 'ascii')
      .digest('base64url');

    const state = crypto.randomBytes(32).toString('base64url');

    const transaction: SsoTransaction = {
      state,
      codeVerifier,
      createdAt: Math.floor(Date.now() / 1000),
      returnTo,
    };

    this.cookies.set(res, SSO_TX_COOKIE, transaction, TX_COOKIE_TTL_SECONDS, {
      sameSite: 'lax',
    });

    const { authorization_endpoint: authorizeEndpoint } =
      await this.discovery.metadata();

    const url = new URL(authorizeEndpoint);

    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);

    res.redirect(url.toString());
  }

  async completeLogin(
    req: Request,
    res: Response,
    query: Record<string, unknown>,
  ): Promise<void> {
    const transaction = this.cookies.get<SsoTransaction>(req, SSO_TX_COOKIE);

    this.cookies.clear(res, SSO_TX_COOKIE, { sameSite: 'lax' });

    if (!transaction) {
      return this.loginFailed(
        req,
        res,
        'login_expired',
        'transacao de login ausente ou ilegivel',
      );
    }

    if (
      typeof query.state !== 'string' ||
      !this.timingSafeEqual(query.state, transaction.state)
    ) {
      return this.loginFailed(
        req,
        res,
        'state_mismatch',
        'state nao confere com a transacao',
      );
    }

    const returnTo = this.safeReturnTo(transaction.returnTo);
    const age = Math.floor(Date.now() / 1000) - transaction.createdAt;

    if (age > TX_COOKIE_TTL_SECONDS) {
      return this.loginFailed(
        req,
        res,
        'login_expired',
        'transacao de login expirada',
        returnTo,
      );
    }

    if (typeof query.iss === 'string' && query.iss !== this.issuer) {
      return this.loginFailed(
        req,
        res,
        'login_failed',
        `resposta veio de outro servidor: iss ${JSON.stringify(query.iss)}`,
        returnTo,
      );
    }

    if (typeof query.error === 'string') {
      return this.loginFailed(
        req,
        res,
        this.codeForAuthorizeError(query.error),
        `o SSO recusou a autorizacao: ${JSON.stringify(query.error)} ${JSON.stringify(query.error_description ?? '')}`,
        returnTo,
      );
    }

    if (typeof query.code !== 'string' || !query.code) {
      return this.loginFailed(
        req,
        res,
        'login_failed',
        'code ausente na resposta do SSO',
        returnTo,
      );
    }

    let tokens: SsoTokenResponse;

    try {
      tokens = await this.requestTokens({
        grant_type: 'authorization_code',
        code: query.code,
        code_verifier: transaction.codeVerifier,
        redirect_uri: this.redirectUri,
      });
    } catch (error) {
      return this.loginFailed(
        req,
        res,
        error instanceof UnauthorizedException
          ? 'login_failed'
          : 'sso_unavailable',
        `troca do code falhou: ${error instanceof Error ? error.message : String(error)}`,
        returnTo,
      );
    }

    this.sessions.write(res, tokens);

    this.bounceTo(res, returnTo);
  }

  private loginFailed(
    req: Request,
    res: Response,
    code: SsoLoginErrorCode,
    reason: string,
    returnTo?: string,
  ): void {
    this.logger.warn(`login nao concluido (${code}): ${reason}`);

    if (!this.loginErrorRedirect || !isPageNavigation(req)) {
      throw new SsoLoginFailedException(code, reason);
    }

    const destination = new URL(this.loginErrorRedirect);

    destination.searchParams.set('auth_error', code);

    if (returnTo) {
      destination.searchParams.set(
        'returnTo',
        this.forNavigation(new URL(returnTo, this.ownOrigin)),
      );
    }

    this.bounceTo(res, this.forNavigation(destination), 'Redirecionando...');
  }

  private codeForAuthorizeError(error: string): SsoLoginErrorCode {
    if (error === 'access_denied') return 'access_denied';

    if (error === 'server_error' || error === 'temporarily_unavailable') {
      return 'sso_unavailable';
    }

    return 'login_failed';
  }

  private forNavigation(url: URL): string {
    return url.origin === this.ownOrigin
      ? `${url.pathname}${url.search}${url.hash}`
      : url.toString();
  }

  loginUrl(returnTo?: string): string {
    const destination = this.safeReturnTo(returnTo);

    return `${this.appBaseUrl}/auth/login?returnTo=${encodeURIComponent(destination)}`;
  }

  safeReturnTo(candidate?: string): string {
    if (!candidate) return this.postLoginRedirect;

    if (/^\/[/\\]/.test(candidate)) return this.postLoginRedirect;

    try {
      const destination = candidate.startsWith('/')
        ? new URL(candidate, this.ownOrigin)
        : new URL(candidate);

      return destination.origin === this.ownOrigin
        ? candidate
        : this.postLoginRedirect;
    } catch {
      return this.postLoginRedirect;
    }
  }

  private bounceTo(
    res: Response,
    destination: string,
    warning = 'Entrando...',
  ): void {
    const escaped = destination.replace(
      /[&<>"']/g,
      (c) =>
        ({
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;',
        })[c] as string,
    );

    res
      .status(200)
      .type('html')
      .set('Cache-Control', 'no-store')
      .send(
        [
          '<!doctype html>',
          '<html lang="pt-br"><head><meta charset="utf-8">',
          `<meta http-equiv="refresh" content="0; url=${escaped}">`,
          `<title>${warning}</title></head>`,
          `<body><p>${warning} <a href="${escaped}">continuar</a></p></body></html>`,
        ].join(''),
      );
  }

  private renew(refreshToken: string): Promise<SsoTokenResponse> {
    const nowMs = Date.now();

    for (const [key, entry] of this.renewals) {
      if (entry.settledAt && nowMs - entry.settledAt > RENEWAL_REUSE_MS) {
        this.renewals.delete(key);
      }
    }

    const existing = this.renewals.get(refreshToken);

    if (existing) return existing.promise;

    const pending: { promise: Promise<SsoTokenResponse>; settledAt?: number } =
      {
        promise: this.requestTokens({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        }),
      };

    pending.promise.then(
      () => {
        pending.settledAt = Date.now();
      },
      () => {
        this.renewals.delete(refreshToken);
      },
    );

    this.renewals.set(refreshToken, pending);

    return pending.promise;
  }

  async forceRefresh(
    session: SsoSessionData,
    res: Response,
    options: { clearOnFailure?: boolean } = {},
  ): Promise<SsoSessionData | null> {
    try {
      const tokens = await this.renew(session.refreshToken);

      return this.sessions.write(res, tokens, session.csrfToken);
    } catch (error) {
      this.logger.warn(
        `renovacao forcada recusada pelo SSO: ${error instanceof Error ? error.message : String(error)}`,
      );

      if (options.clearOnFailure !== false) this.sessions.clear(res);

      return null;
    }
  }

  async refreshIfNeeded(
    session: SsoSessionData,
    res: Response,
  ): Promise<SsoSessionData | null> {
    const now = Math.floor(Date.now() / 1000);

    if (session.expiresAt - now > this.refreshSkewSeconds) {
      return session;
    }

    try {
      const tokens = await this.renew(session.refreshToken);

      return this.sessions.write(res, tokens, session.csrfToken);
    } catch (error) {
      this.logger.warn(
        `renovacao recusada pelo SSO: ${error instanceof Error ? error.message : String(error)}`,
      );

      this.sessions.clear(res);
      return null;
    }
  }

  async currentAccessToken(
    req: Request,
    res: Response,
  ): Promise<{ access_token: string; token_type: 'Bearer'; expires_in: number }> {
    const stored = this.sessions.read(req);

    if (!stored) {
      throw new UnauthorizedException('sessao ausente ou invalida');
    }

    const session = await this.refreshIfNeeded(stored, res);

    if (!session) {
      throw new UnauthorizedException('sessao expirada; refaca o login');
    }

    return {
      access_token: session.accessToken,
      token_type: 'Bearer',
      expires_in: Math.max(
        0,
        session.expiresAt - Math.floor(Date.now() / 1000),
      ),
    };
  }

  async logout(req: Request, res: Response): Promise<void> {
    const session = this.sessions.read(req);

    this.sessions.clear(res);
    this.cookies.clear(res, SSO_TX_COOKIE, { sameSite: 'lax' });

    if (!session?.refreshToken) return;

    try {
      const { revocation_endpoint: revocationEndpoint } =
        await this.discovery.metadata();

      if (!revocationEndpoint) {
        this.logger.warn(
          'o SSO nao anuncia revocation_endpoint; o refresh token seguira valido ate expirar',
        );
        return;
      }

      await fetch(revocationEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          token: session.refreshToken,
          token_type_hint: 'refresh_token',
          client_id: this.clientId,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await this.assertions.build(),
        }),
      });
    } catch (error) {
      this.logger.error(
        `falha ao revogar o refresh token no SSO: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private async requestTokens(
    grant: Record<string, string>,
  ): Promise<SsoTokenResponse> {
    const { token_endpoint: tokenEndpoint } = await this.discovery.metadata();

    const res = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...grant,
        client_id: this.clientId,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await this.assertions.build(),
      }),
    });

    const body = (await res.json().catch(() => null)) as
      | (SsoTokenResponse & Partial<SsoTokenError>)
      | null;

    if (!res.ok || !body) {
      const detail = body?.error
        ? `${body.error}: ${body.error_description ?? ''}`.trim()
        : `HTTP ${res.status}`;

      throw res.status >= 500
        ? new BadGatewayException(`SSO indisponivel (${detail})`)
        : new UnauthorizedException(`SSO recusou a troca (${detail})`);
    }

    if (!body.access_token || !body.refresh_token) {
      throw new BadGatewayException('resposta do SSO sem os tokens esperados');
    }

    return body;
  }

  private timingSafeEqual(a: string, b: string): boolean {
    const left = Buffer.from(a);
    const right = Buffer.from(b);

    return left.length === right.length && crypto.timingSafeEqual(left, right);
  }
}
