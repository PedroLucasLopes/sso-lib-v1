import { Inject, Injectable, Logger } from '@nestjs/common';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type { AuthorizationServerMetadata } from '../dto/ssoSession.dto';

@Injectable()
export class SsoDiscoveryService {
  private readonly logger = new Logger(SsoDiscoveryService.name);
  private readonly issuer: string;
  private readonly internalBaseUrl: string;
  private cached: AuthorizationServerMetadata | null = null;
  private inFlight: Promise<AuthorizationServerMetadata> | null = null;

  constructor(@Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions) {
    this.issuer = options.issuer.replace(/\/+$/, '');
    this.internalBaseUrl = (options.internalBaseUrl ?? options.issuer).replace(
      /\/+$/,
      '',
    );
  }

  async metadata(): Promise<AuthorizationServerMetadata> {
    if (this.cached) return this.cached;

    this.inFlight ??= this.fetchMetadata();

    try {
      this.cached = await this.inFlight;
      return this.cached;
    } finally {
      this.inFlight = null;
    }
  }

  private async fetchMetadata(): Promise<AuthorizationServerMetadata> {
    const url = `${this.internalBaseUrl}/.well-known/oauth-authorization-server`;
    const res = await fetch(url);

    if (!res.ok) {
      throw new Error(`discovery do SSO falhou: HTTP ${res.status} em ${url}`);
    }

    const metadata = (await res.json()) as AuthorizationServerMetadata;

    if (metadata.issuer !== this.issuer) {
      throw new Error(
        `issuer do discovery (${metadata.issuer}) diferente do configurado (${this.issuer})`,
      );
    }

    this.logger.log(`discovery do SSO carregado de ${url}`);

    return {
      issuer: metadata.issuer,
      authorization_endpoint: metadata.authorization_endpoint,
      token_endpoint: this.toInternal(metadata.token_endpoint),
      jwks_uri: this.toInternal(metadata.jwks_uri),
      revocation_endpoint: metadata.revocation_endpoint
        ? this.toInternal(metadata.revocation_endpoint)
        : undefined,
      permissions_endpoint: metadata.permissions_endpoint
        ? this.toInternal(metadata.permissions_endpoint)
        : undefined,
      introspection_endpoint: metadata.introspection_endpoint
        ? this.toInternal(metadata.introspection_endpoint)
        : undefined,
      token_endpoint_public: metadata.token_endpoint,
    };
  }

  private toInternal(endpoint: string): string {
    if (this.internalBaseUrl === this.issuer) return endpoint;

    return endpoint.startsWith(this.issuer)
      ? `${this.internalBaseUrl}${endpoint.slice(this.issuer.length)}`
      : endpoint;
  }
}
