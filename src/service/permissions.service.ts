import { Inject, Injectable, Logger } from '@nestjs/common';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type { SsoPermission } from '../dto/ssoSession.dto';
import {
  CLIENT_ASSERTION_TYPE,
  SsoClientAssertionService,
} from './clientAssertion.service';
import { SsoDiscoveryService } from './discovery.service';

interface PermissionSetResponse {
  role: string;
  hash: string;
  permissions: SsoPermission[];
}

/**
 * Resolve a claim `roles` do access token no conjunto de rotas que o papel
 * libera, e guarda o resultado em memoria.
 *
 * Existe porque o token carrega o PAPEL, nao a lista enumerada de rotas
 * (RFC 9068 secao 2.2.3.1). Antes a lista ia dentro do token, que crescia com
 * o numero de rotas do projeto: com 38 rotas o token chegou a 3 KB e o cookie
 * de sessao passou do limite de 4 KB do navegador, que o descartava calado.
 *
 * A chave de cache inclui o hash que o SSO devolve. Mudou a permissao do
 * papel, muda o hash, e a entrada velha simplesmente deixa de ser consultada.
 * Sem TTL adivinhado e sem precisar de aviso.
 */
@Injectable()
export class SsoPermissionsService {
  private readonly logger = new Logger(SsoPermissionsService.name);
  private readonly clientId: string;
  private readonly cache = new Map<string, SsoPermission[]>();
  private readonly inFlight = new Map<string, Promise<SsoPermission[]>>();

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private discovery: SsoDiscoveryService,
    private assertions: SsoClientAssertionService,
  ) {
    this.clientId = options.clientId;
  }

  /** Une os papeis do token num conjunto so de permissoes. */
  async forRoles(roles: string[], hash: string): Promise<SsoPermission[]> {
    const sets = await Promise.all(
      roles.map((role) => this.forRole(role, hash)),
    );

    return sets.flat();
  }

  private async forRole(role: string, hash: string): Promise<SsoPermission[]> {
    const key = `${role}:${hash}`;
    const cached = this.cache.get(key);

    if (cached) return cached;

    // Varias requisicoes simultaneas apos um deploy compartilham uma busca so.
    const pending = this.inFlight.get(key);

    if (pending) return pending;

    const promise = this.fetchRole(role, key);

    this.inFlight.set(key, promise);

    try {
      return await promise;
    } finally {
      this.inFlight.delete(key);
    }
  }

  private async fetchRole(
    role: string,
    key: string,
  ): Promise<SsoPermission[]> {
    const { permissions_endpoint: endpoint } = await this.discovery.metadata();

    if (!endpoint) {
      throw new Error('o SSO nao anuncia permissions_endpoint');
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        role,
        client_id: this.clientId,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await this.assertions.build(),
      }),
    });

    if (!res.ok) {
      throw new Error(
        `nao foi possivel resolver o papel ${role}: HTTP ${res.status}`,
      );
    }

    const body = (await res.json()) as PermissionSetResponse;

    // Guarda sob o hash que o SSO devolveu, e nao sob o que veio no token:
    // se divergirem, a proxima requisicao busca de novo em vez de servir
    // permissao desatualizada de um cache com chave errada.
    this.cache.set(`${role}:${body.hash}`, body.permissions);

    if (`${role}:${body.hash}` !== key) {
      this.logger.warn(
        `hash de permissoes do papel ${role} divergiu do token; o SSO mudou desde a emissao`,
      );
    }

    this.logger.log(
      `papel ${role} resolvido: ${body.permissions.length} rota(s), hash ${body.hash}`,
    );

    return body.permissions;
  }
}
