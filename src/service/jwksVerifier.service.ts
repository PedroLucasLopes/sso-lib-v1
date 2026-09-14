import { Inject, Injectable, Logger } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type { AccessTokenClaims } from '../dto/ssoSession.dto';
import { SsoDiscoveryService } from './discovery.service';

/**
 * Estende o JsonWebKey do Node em vez de redeclarar os campos: `createPublicKey`
 * exige a assinatura de indice desse tipo para aceitar o formato `jwk`.
 */
type Jwk = crypto.JsonWebKey & {
  kid?: string;
  alg?: string;
  use?: string;
};

/**
 * Verificacao do access token contra o JWKS publicado pelo SSO.
 *
 * Substitui a verificacao com segredo simetrico. A diferenca nao e de
 * conveniencia: com segredo compartilhado, toda aplicacao capaz de VERIFICAR
 * tambem era capaz de EMITIR token para qualquer outro projeto. Aqui a
 * aplicacao so tem a chave publica.
 */
@Injectable()
export class SsoJwksVerifierService {
  /** Cooldown entre buscas do JWKS. Sem ele, token com `kid` aleatorio vira DoS. */
  private static readonly REFETCH_COOLDOWN_MS = 60_000;

  private readonly logger = new Logger(SsoJwksVerifierService.name);
  private readonly issuer: string;
  private readonly clientId: string;

  private keys = new Map<string, crypto.KeyObject>();
  private lastFetchAt = 0;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private discovery: SsoDiscoveryService,
  ) {
    this.issuer = options.issuer.replace(/\/+$/, '');
    this.clientId = options.clientId;
  }

  async verify(token: string): Promise<AccessTokenClaims> {
    const parts = token.split('.');

    if (parts.length !== 3) {
      throw new Error('token malformado');
    }

    const [rawHeader, rawPayload, rawSignature] = parts;
    const header = this.decodeSegment<{ alg?: string; kid?: string }>(rawHeader);

    // Allowlist explicita de algoritmo. Aceitar o `alg` do proprio token e a
    // brecha classica de confusao de algoritmo: `none` passa direto, e HS256
    // permitiria assinar com a chave publica, que e conhecida.
    if (header.alg !== 'RS256') {
      throw new Error(`algoritmo nao aceito: ${String(header.alg)}`);
    }

    if (!header.kid) {
      throw new Error('token sem kid no header');
    }

    const key = await this.keyFor(header.kid);

    const valid = crypto.verify(
      'sha256',
      Buffer.from(`${rawHeader}.${rawPayload}`),
      key,
      Buffer.from(rawSignature, 'base64url'),
    );

    if (!valid) {
      throw new Error('assinatura invalida');
    }

    const claims = this.decodeSegment<AccessTokenClaims>(rawPayload);
    const now = Math.floor(Date.now() / 1000);

    if (claims.iss !== this.issuer) {
      throw new Error(`iss inesperado: ${claims.iss}`);
    }

    // RFC 9700 secao 2.3: token de um projeto nao pode valer em outro.
    if (claims.aud !== this.clientId) {
      throw new Error('token emitido para outro cliente');
    }

    if (typeof claims.exp !== 'number' || claims.exp <= now) {
      throw new Error('token expirado');
    }

    return claims;
  }

  private async keyFor(kid: string): Promise<crypto.KeyObject> {
    const cached = this.keys.get(kid);

    if (cached) return cached;

    // `kid` novo costuma significar rotacao de chave no SSO, entao vale
    // rebuscar. O cooldown evita que isso vire vetor de carga.
    if (Date.now() - this.lastFetchAt > SsoJwksVerifierService.REFETCH_COOLDOWN_MS) {
      await this.refreshKeys();
    }

    const key = this.keys.get(kid);

    if (!key) {
      throw new Error(`kid ${kid} nao encontrado no JWKS do SSO`);
    }

    return key;
  }

  private async refreshKeys(): Promise<void> {
    const { jwks_uri: jwksUri } = await this.discovery.metadata();
    const res = await fetch(jwksUri);

    if (!res.ok) {
      throw new Error(`JWKS indisponivel: HTTP ${res.status}`);
    }

    const { keys } = (await res.json()) as { keys: Jwk[] };
    const next = new Map<string, crypto.KeyObject>();

    for (const jwk of keys) {
      if (!jwk.kid || jwk.kty !== 'RSA') continue;
      if (jwk.alg && jwk.alg !== 'RS256') continue;

      try {
        next.set(jwk.kid, crypto.createPublicKey({ key: jwk, format: 'jwk' }));
      } catch {
        this.logger.warn(`chave ${jwk.kid} do JWKS e invalida e foi ignorada`);
      }
    }

    this.keys = next;
    this.lastFetchAt = Date.now();

    this.logger.log(`JWKS atualizado: ${next.size} chave(s)`);
  }

  private decodeSegment<T>(segment: string): T {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as T;
  }
}
