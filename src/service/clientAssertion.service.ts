import { Inject, Injectable } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import { SsoDiscoveryService } from './discovery.service';

export const CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

@Injectable()
export class SsoClientAssertionService {
  private static readonly LIFETIME_SECONDS = 60;

  private readonly clientId: string;
  private readonly privateKey: crypto.KeyObject;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private discovery: SsoDiscoveryService,
  ) {
    this.clientId = options.clientId;

    try {
      this.privateKey = crypto.createPrivateKey(options.clientPrivateKeyPem);
    } catch {
      throw new Error(
        'clientPrivateKeyPem nao e uma chave privada valida em PEM (PKCS8)',
      );
    }

    if (this.privateKey.asymmetricKeyType !== 'rsa') {
      throw new Error('clientPrivateKeyPem precisa ser uma chave RSA (RS256)');
    }
  }

  async build(): Promise<string> {
    const { token_endpoint_public: tokenEndpoint } =
      await this.discovery.metadata();

    const now = Math.floor(Date.now() / 1000);

    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = {
      iss: this.clientId,
      sub: this.clientId,
      aud: tokenEndpoint,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + SsoClientAssertionService.LIFETIME_SECONDS,
    };

    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value)).toString('base64url');

    const signingInput = `${encode(header)}.${encode(payload)}`;

    const signature = crypto
      .sign('sha256', Buffer.from(signingInput), this.privateKey)
      .toString('base64url');

    return `${signingInput}.${signature}`;
  }
}
