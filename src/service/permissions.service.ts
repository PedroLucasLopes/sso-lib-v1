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

interface CachedSet {
  permissions: SsoPermission[];
  fetchedAt: number;
}

/**
 * Quanto tempo um conjunto guardado vale. O hash so muda dentro do token quando
 * ele e renovado, e isso leva ate 15 minutos; sem este prazo, uma permissao
 * revogada no console continuaria valendo esse tempo todo.
 */
const MAX_AGE_MS = 60_000;

/**
 * Intervalo minimo entre duas buscas forcadas do mesmo papel. Uma rota negada
 * repetidas vezes nao vira uma chamada ao SSO por requisicao.
 */
const REVALIDATE_INTERVAL_MS = 5_000;

/**
 * Resolve a claim `roles` do access token no conjunto de rotas que o papel
 * libera, e guarda o resultado em memoria.
 *
 * Existe porque o token carrega o PAPEL, nao a lista enumerada de rotas
 * (RFC 9068 secao 2.2.3.1). Antes a lista ia dentro do token, que crescia com
 * o numero de rotas do projeto: com 38 rotas o token chegou a 3 KB e o cookie
 * de sessao passou do limite de 4 KB do navegador, que o descartava calado.
 *
 * O banco do SSO e a fonte de verdade, e as mudancas feitas no console chegam
 * aqui por dois caminhos:
 *
 * - **Concessao:** antes de negar uma rota, o guard pede uma busca nova. A
 *   permissao recem-concedida vale na requisicao seguinte.
 * - **Revogacao:** cada conjunto vale no maximo 60 segundos. Depois disso, a
 *   proxima requisicao busca de novo.
 */
@Injectable()
export class SsoPermissionsService {
  private readonly logger = new Logger(SsoPermissionsService.name);
  private readonly clientId: string;
  private readonly cache = new Map<string, CachedSet>();
  private readonly lastFetch = new Map<string, number>();
  private readonly inFlight = new Map<string, Promise<SsoPermission[]>>();

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private discovery: SsoDiscoveryService,
    private assertions: SsoClientAssertionService,
  ) {
    this.clientId = options.clientId;
  }

  /**
   * Une os papeis do token num conjunto so de permissoes. `revalidate` pede uma
   * busca nova, respeitando o intervalo minimo entre buscas do mesmo papel.
   */
  async forRoles(
    roles: string[],
    hash: string,
    options: { revalidate?: boolean } = {},
  ): Promise<SsoPermission[]> {
    const sets = await Promise.all(
      roles.map((role) => this.forRole(role, hash, options.revalidate === true)),
    );

    return sets.flat();
  }

  private async forRole(
    role: string,
    hash: string,
    revalidate: boolean,
  ): Promise<SsoPermission[]> {
    const key = `${role}:${hash}`;
    const cached = this.cache.get(key);
    const now = Date.now();

    if (cached) {
      const fresh = now - cached.fetchedAt < MAX_AGE_MS;
      const justFetched =
        now - (this.lastFetch.get(role) ?? 0) < REVALIDATE_INTERVAL_MS;

      if (revalidate ? justFetched : fresh) return cached.permissions;
    }

    // Varias requisicoes simultaneas compartilham uma busca so por papel.
    const pending = this.inFlight.get(role) ?? this.startFetch(role, key);

    try {
      return await pending;
    } catch (error) {
      /* SSO fora do ar: o ultimo conjunto conhecido segue valendo ate ele
       * voltar. A janela e curta por construcao, porque sem o SSO nenhum token
       * se renova e o access token dura 15 minutos. Sem conjunto guardado nao
       * ha o que servir, e o erro sobe. */
      if (!cached) throw error;

      this.logger.warn(
        `SSO indisponivel ao resolver o papel ${role}; mantido o ultimo conjunto conhecido`,
      );

      return cached.permissions;
    }
  }

  private startFetch(role: string, key: string): Promise<SsoPermission[]> {
    const promise = this.fetchRole(role, key).finally(() => {
      this.inFlight.delete(role);
    });

    this.inFlight.set(role, promise);

    return promise;
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

    /* Papel que o SSO nao conhece mais, apagado ou renomeado, nao alcanca nada
     * ate o token renovar com o nome novo. Isso nao e SSO fora do ar: manter o
     * conjunto antigo deixaria valer o que ja nao existe. */
    if (res.status === 404) {
      const empty: CachedSet = { permissions: [], fetchedAt: Date.now() };

      this.cache.set(key, empty);
      this.lastFetch.set(role, empty.fetchedAt);
      this.logger.warn(`papel ${role} nao existe no SSO; nenhuma rota liberada`);

      return empty.permissions;
    }

    if (!res.ok) {
      throw new Error(
        `nao foi possivel resolver o papel ${role}: HTTP ${res.status}`,
      );
    }

    const body = (await res.json()) as PermissionSetResponse;
    const entry: CachedSet = {
      permissions: body.permissions,
      fetchedAt: Date.now(),
    };

    /* Guarda sob o hash que o SSO devolveu e tambem sob o que veio no token.
     * Quando os dois divergem, o conjunto novo e o que vale agora; sem a segunda
     * chave, todo pedido com o token antigo buscaria de novo ate ele renovar. */
    this.cache.set(`${role}:${body.hash}`, entry);
    this.cache.set(key, entry);
    this.lastFetch.set(role, entry.fetchedAt);

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
