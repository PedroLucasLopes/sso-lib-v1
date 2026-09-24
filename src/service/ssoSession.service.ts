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

const RENEWED = Symbol('sso-client:renewed-session');

@Injectable()
export class SsoSessionService {
  private readonly maxAgeSeconds: number;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private cookies: SsoCookieService,
  ) {
    this.maxAgeSeconds = options.sessionMaxAgeSeconds ?? 90 * 24 * 60 * 60;
  }

  get cookieName(): string {
    return this.cookies.name(SSO_SESSION_COOKIE);
  }

  get csrfCookieName(): string {
    return this.cookies.name(SSO_CSRF_COOKIE);
  }

  read(req: Request): SsoSessionData | null {
    const renewed = (req as Request & { [RENEWED]?: SsoSessionData })[RENEWED];

    if (renewed) return renewed;

    return this.cookies.get<SsoSessionData>(req, SSO_SESSION_COOKIE);
  }

  remember(req: Request, session: SsoSessionData): void {
    (req as Request & { [RENEWED]?: SsoSessionData })[RENEWED] = session;
  }

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
