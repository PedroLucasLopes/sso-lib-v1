import { Inject, Injectable } from '@nestjs/common';
import type { Request, Response } from 'express';
import * as crypto from 'node:crypto';
import { SsoCookieService } from '../cookie/cookie.service';
import {
  SSO_CLIENT_OPTIONS,
  SSO_CSRF_COOKIE,
  SSO_SESSION_COOKIE,
} from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type { SsoSessionData, SsoTokenResponse } from '../dto/ssoSession.dto';

/**
 * Sessao da aplicacao, materializada num cookie cifrado.
 *
 * A sessao existe para guardar o REFRESH token do lado do servidor, que e o
 * que a RFC 10017 secao 6.2.2.2 pede do token-mediating backend: o refresh
 * token nao chega ao navegador, so o access token chega, e por
 * `GET /auth/token`.
 *
 * O cookie e cifrado porque carrega credencial. Ele tambem carrega o access
 * token corrente, o que evita ida ao SSO a cada navegacao direta.
 *
 * Junto dele vai um segundo cookie, `app_csrf`, LEGIVEL e sem cifra. Ele
 * carrega o mesmo token anti-CSRF que esta dentro do cifrado, para o front
 * poder devolve-lo no header. A RFC 10017 secao 6.2.3.2 exige que este padrao
 * se defenda de CSRF, e autenticacao por cookie sozinha nao se defende: o
 * navegador anexa o cookie mesmo quando quem disparou a requisicao foi outro
 * site.
 */
@Injectable()
export class SsoSessionService {
  private readonly maxAgeSeconds: number;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private cookies: SsoCookieService,
  ) {
    // O cookie acompanha o REFRESH token, nao o access token: e ele que
    // determina por quanto tempo a sessao ainda pode ser renovada. Se este
    // valor ficar menor que o do SSO, o navegador descarta o cookie antes de
    // o refresh token expirar, e a pessoa e mandada ao login sem razao
    // aparente do lado do servidor.
    this.maxAgeSeconds = options.sessionMaxAgeSeconds ?? 90 * 24 * 60 * 60;
  }

  /** Nome real do cookie, que muda com `cookieSecure` por causa do `__Host-`. */
  get cookieName(): string {
    return this.cookies.name(SSO_SESSION_COOKIE);
  }

  /** Nome real do cookie legivel do anti-CSRF. O front le isto de `/auth/me`. */
  get csrfCookieName(): string {
    return this.cookies.name(SSO_CSRF_COOKIE);
  }

  read(req: Request): SsoSessionData | null {
    return this.cookies.get<SsoSessionData>(req, SSO_SESSION_COOKIE);
  }

  /**
   * Grava a sessao. `csrfToken` chega preenchido na renovacao silenciosa, para
   * que o valor sobreviva: trocar o token a cada refresh derrubaria a copia
   * que o front ja tem, e a proxima escrita dele falharia sem motivo.
   */
  write(
    res: Response,
    tokens: SsoTokenResponse,
    csrfToken?: string,
  ): SsoSessionData {
    const session: SsoSessionData = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Math.floor(Date.now() / 1000) + tokens.expires_in,
      csrfToken: csrfToken ?? crypto.randomBytes(32).toString('base64url'),
    };

    this.cookies.set(res, SSO_SESSION_COOKIE, session, this.maxAgeSeconds);

    this.cookies.setReadable(
      res,
      SSO_CSRF_COOKIE,
      session.csrfToken,
      this.maxAgeSeconds,
    );

    return session;
  }

  clear(res: Response): void {
    this.cookies.clear(res, SSO_SESSION_COOKIE);
    this.cookies.clearReadable(res, SSO_CSRF_COOKIE);
  }
}
