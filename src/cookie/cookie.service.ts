import { Inject, Injectable } from '@nestjs/common';
import type { CookieOptions, Request, Response } from 'express';
import * as crypto from 'node:crypto';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import { openCompact, readKey, sealCompact } from './aead';

@Injectable()
export class SsoCookieService {
  private readonly key: Buffer;
  private readonly secure: boolean;
  private readonly sameSite: 'lax' | 'strict' | 'none';
  private readonly prefix: string;

  constructor(@Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions) {
    this.key = readKey(options.cookieSecret, 'cookieSecret');
    this.secure = options.cookieSecure ?? true;
    this.sameSite = options.cookieSameSite ?? 'strict';

    this.prefix =
      options.cookiePrefix ??
      crypto.createHash('sha256').update(options.clientId).digest('hex').slice(0, 8);
  }

  name(base: string): string {
    const name = `${this.prefix}_${base}`;

    return this.secure ? `__Host-${name}` : name;
  }

  set(
    res: Response,
    base: string,
    payload: unknown,
    maxAgeSeconds: number,
    overrides: Partial<CookieOptions> = {},
  ): void {
    res.cookie(
      this.name(base),
      sealCompact(this.key, JSON.stringify(payload)),
      {
        httpOnly: true,
        secure: this.secure,
        sameSite: this.sameSite,
        path: '/',
        maxAge: maxAgeSeconds * 1000,
        ...overrides,
      },
    );
  }

  setReadable(
    res: Response,
    base: string,
    value: string,
    maxAgeSeconds: number,
  ): void {
    res.cookie(this.name(base), value, {
      httpOnly: false,
      secure: this.secure,
      sameSite: this.sameSite,
      path: '/',
      maxAge: maxAgeSeconds * 1000,
    });
  }

  clearReadable(res: Response, base: string): void {
    res.clearCookie(this.name(base), {
      httpOnly: false,
      secure: this.secure,
      sameSite: this.sameSite,
      path: '/',
    });
  }

  get<T>(req: Request, base: string): T | null {
    const jar = req.cookies as Record<string, string> | undefined;
    const raw = jar?.[this.name(base)];

    if (!raw) return null;

    const plaintext = openCompact(this.key, raw);

    if (!plaintext) return null;

    try {
      return JSON.parse(plaintext) as T;
    } catch {
      return null;
    }
  }

  clear(
    res: Response,
    base: string,
    overrides: Partial<CookieOptions> = {},
  ): void {
    res.clearCookie(this.name(base), {
      httpOnly: true,
      secure: this.secure,
      sameSite: this.sameSite,
      path: '/',
      ...overrides,
    });
  }
}
