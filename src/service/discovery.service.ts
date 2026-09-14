import { Inject, Injectable, Logger } from '@nestjs/common';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type { AuthorizationServerMetadata } from '../dto/ssoSession.dto';

/**
 * Descoberta dos endpoints do Authorization Server (RFC 8414).
 *
 * Ler os endpoints do proprio servidor evita espalhar URL fixa por aplicacao:
 * se o SSO mudar de caminho, ninguem precisa redeployar. A busca e preguicosa
 * e o resultado fica em memoria, entao um SSO fora do ar no boot nao impede a
 * aplicacao de subir.
 */
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

    // Duas requisicoes simultaneas no boot compartilham a mesma busca.
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

    // RFC 8414 secao 3.3: o `issuer` devolvido tem de ser identico ao
    // configurado. Divergencia significa configuracao apontando para o
    // servidor errado, e a checagem NAO afrouxa por causa do endereco interno.
    if (metadata.issuer !== this.issuer) {
      throw new Error(
        `issuer do discovery (${metadata.issuer}) diferente do configurado (${this.issuer})`,
      );
    }

    this.logger.log(`discovery do SSO carregado de ${url}`);

    return {
      issuer: metadata.issuer,
      // Publico: quem abre e o navegador do usuario.
      authorization_endpoint: metadata.authorization_endpoint,
      // Internos: chamados por este processo.
      token_endpoint: this.toInternal(metadata.token_endpoint),
      jwks_uri: this.toInternal(metadata.jwks_uri),
      revocation_endpoint: metadata.revocation_endpoint
        ? this.toInternal(metadata.revocation_endpoint)
        : undefined,
      permissions_endpoint: metadata.permissions_endpoint
        ? this.toInternal(metadata.permissions_endpoint)
        : undefined,
      // Publico: e a audiencia que o SSO espera na asserção de cliente.
      token_endpoint_public: metadata.token_endpoint,
    };
  }

  /** Troca o prefixo publico pelo endereco de rede, quando houver um. */
  private toInternal(endpoint: string): string {
    if (this.internalBaseUrl === this.issuer) return endpoint;

    return endpoint.startsWith(this.issuer)
      ? `${this.internalBaseUrl}${endpoint.slice(this.issuer.length)}`
      : endpoint;
  }
}
