import { Inject, Injectable } from '@nestjs/common';
import type { CookieOptions, Request, Response } from 'express';
import * as crypto from 'node:crypto';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import { openCompact, readKey, sealCompact } from './aead';

/**
 * Cookies cifrados da aplicacao cliente.
 *
 * RFC 10017 secao 6.1.3.2: Secure e HttpOnly sao MUST; SameSite, `path=/`,
 * ausencia de Domain e prefixo `__Host-` sao SHOULD.
 *
 * O cookie de transacao e sempre `lax`, mesmo quando a sessao e `strict`: o
 * retorno do SSO pode ser uma navegacao cross-site, e `Strict` nao acompanha
 * esse salto.
 */
@Injectable()
export class SsoCookieService {
  private readonly key: Buffer;
  private readonly secure: boolean;
  private readonly sameSite: 'lax' | 'strict' | 'none';
  private readonly prefix: string;

  constructor(@Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions) {
    this.key = readKey(options.cookieSecret, 'cookieSecret');
    this.secure = options.cookieSecure ?? true;
    // `strict` como padrao: a RFC 10017 secao 6.1.3.2 pede, e o retorno do
    // login nao quebra mais porque o callback devolve um documento da propria
    // origem em vez de um 302. Ver `bounceTo` em ssoOAuth.service.
    this.sameSite = options.cookieSameSite ?? 'strict';

    // Deriva do clientId, que ja e unico por aplicacao. Oito digitos bastam:
    // isto separa vizinhos, nao guarda segredo.
    this.prefix =
      options.cookiePrefix ??
      crypto.createHash('sha256').update(options.clientId).digest('hex').slice(0, 8);
  }

  /**
   * O prefixo `__Host-` so vale em cookie Secure, com Path=/ e sem Domain.
   * Sobre HTTP o navegador recusaria, entao o prefixo cai junto com o Secure.
   */
  name(base: string): string {
    const nome = `${this.prefix}_${base}`;

    return this.secure ? `__Host-${nome}` : nome;
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

  /**
   * Cookie LEGIVEL pelo JavaScript da pagina, e sem cifra.
   *
   * Existe so para o token anti-CSRF, que precisa chegar ao front para ele
   * devolver no header. Nao e segredo: o valor so tem serventia para quem ja
   * esta na origem certa, e a copia que vale e a que vive dentro do cookie de
   * sessao cifrado. Nunca use isto para credencial.
   */
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

  /**
   * Path e nome precisam bater com os do `set`, senao o navegador guarda um
   * segundo cookie em vez de apagar o primeiro. `overrides` existe para o
   * cookie de transacao, gravado sempre como `lax`: apagar com outro
   * SameSite funcionaria, porque a identidade do cookie e (nome, dominio,
   * caminho), mas deixaria os dois lados contraditorios.
   */
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
