import { Inject, Injectable, Logger } from '@nestjs/common';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import {
  CLIENT_ASSERTION_TYPE,
  SsoClientAssertionService,
} from './clientAssertion.service';
import { SsoDiscoveryService } from './discovery.service';

/** O que o SSO diz do grant de um token, reduzido ao que o guard usa. */
export interface SsoGrantState {
  active: boolean;
  /** O papel da pessoa agora, lido do banco do SSO. */
  roles?: string[];
  /** A impressao digital do conjunto desse papel agora. */
  perm?: string;
}

interface CachedState {
  state: SsoGrantState;
  checkedAt: number;
}

const DEFAULT_CHECK_SECONDS = 30;

/** Acima disto, o mapa se limpa. Tokens giram a cada 15 minutos. */
const MAX_ENTRIES = 5_000;

/**
 * Pergunta ao SSO se o grant de um access token continua valendo, e qual e o
 * papel da pessoa agora (introspeccao, RFC 7662).
 *
 * O access token e assinado e conferido sem consulta, e por isso continuava
 * valendo ate expirar depois de o SSO mudar de ideia: papel trocado, pessoa
 * tirada do projeto, aplicacao suspensa, logout. O guard pergunta aqui, no
 * maximo uma vez por token a cada `grantCheckSeconds`, e age conforme a
 * resposta: grant encerrado derruba a sessao, papel diferente do token pede um
 * token novo na hora.
 *
 * A RFC 7662 secao 4 chama o prazo de guarda de janela em que um token revogado
 * ainda parece valido. E ela que `grantCheckSeconds` controla, e ela fica em 30
 * segundos em vez dos 15 minutos da vida do token.
 *
 * **Quando nao da para perguntar**, o guard segue com o que o token diz, que e o
 * comportamento de antes desta checagem:
 *
 * - SSO que ainda nao anuncia `introspection_endpoint`: a checagem desliga;
 * - SSO fora do ar ou limitando requisicoes: vale o ultimo estado conhecido, ou
 *   o token, se nunca houve resposta. A janela continua curta, porque sem o SSO
 *   nenhum token se renova e o access token dura 15 minutos.
 *
 * **A excecao e o 401.** O SSO so recusa autenticar esta aplicacao quando ela
 * foi suspensa ou a chave dela foi revogada, e ai nenhuma sessao dela vale mais.
 */
@Injectable()
export class SsoIntrospectionService {
  private readonly logger = new Logger(SsoIntrospectionService.name);
  private readonly clientId: string;
  private readonly maxAgeMs: number;
  private readonly cache = new Map<string, CachedState>();
  private readonly inFlight = new Map<string, Promise<SsoGrantState | null>>();

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private discovery: SsoDiscoveryService,
    private assertions: SsoClientAssertionService,
  ) {
    this.clientId = options.clientId;
    this.maxAgeMs = (options.grantCheckSeconds ?? DEFAULT_CHECK_SECONDS) * 1000;
  }

  /**
   * O estado do grant do token, ou `null` quando nao da para saber. `fresh`
   * ignora a janela, para quem precisa da resposta de agora, como
   * `GET /auth/me`.
   */
  async check(
    token: string,
    jti: string,
    options: { fresh?: boolean } = {},
  ): Promise<SsoGrantState | null> {
    const cached = this.cache.get(jti);

    if (
      cached &&
      !options.fresh &&
      Date.now() - cached.checkedAt < this.maxAgeMs
    ) {
      return cached.state;
    }

    // Requisicoes simultaneas do mesmo token esperam a mesma pergunta.
    const pending =
      this.inFlight.get(jti) ?? this.start(token, jti, cached ?? null);

    return pending;
  }

  /**
   * O guard acabou de renovar por causa de uma mudanca: o token novo nasce com
   * o estado que motivou a renovacao, sem perguntar de novo em seguida.
   */
  remember(jti: string, state: SsoGrantState): void {
    this.store(jti, state);
  }

  private start(
    token: string,
    jti: string,
    cached: CachedState | null,
  ): Promise<SsoGrantState | null> {
    const promise = this.introspect(token, jti, cached).finally(() => {
      this.inFlight.delete(jti);
    });

    this.inFlight.set(jti, promise);

    return promise;
  }

  private async introspect(
    token: string,
    jti: string,
    cached: CachedState | null,
  ): Promise<SsoGrantState | null> {
    let endpoint: string | undefined;

    try {
      ({ introspection_endpoint: endpoint } = await this.discovery.metadata());
    } catch (error) {
      return this.fallback(cached, error);
    }

    if (!endpoint) return null;

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token,
          token_type_hint: 'access_token',
          client_id: this.clientId,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await this.assertions.build(),
        }),
      });

      if (res.status === 401) {
        this.logger.warn(
          'o SSO recusou autenticar esta aplicacao na introspeccao: projeto suspenso ou chave revogada',
        );

        const inativo: SsoGrantState = { active: false };

        this.store(jti, inativo);

        return inativo;
      }

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const body = (await res.json()) as {
        active?: unknown;
        roles?: unknown;
        perm?: unknown;
      };

      const state: SsoGrantState =
        body.active === true
          ? {
              active: true,
              roles: Array.isArray(body.roles)
                ? body.roles.filter(
                    (role): role is string => typeof role === 'string',
                  )
                : undefined,
              perm: typeof body.perm === 'string' ? body.perm : undefined,
            }
          : { active: false };

      this.store(jti, state);

      return state;
    } catch (error) {
      return this.fallback(cached, error);
    }
  }

  private fallback(
    cached: CachedState | null,
    error: unknown,
  ): SsoGrantState | null {
    this.logger.warn(
      `introspeccao indisponivel (${error instanceof Error ? error.message : String(error)}); ` +
        (cached
          ? 'mantido o ultimo estado conhecido'
          : 'seguindo com o que o token diz'),
    );

    return cached?.state ?? null;
  }

  private store(jti: string, state: SsoGrantState): void {
    if (this.cache.size >= MAX_ENTRIES) this.prune();

    this.cache.set(jti, { state, checkedAt: Date.now() });
  }

  /** Tira o que ja saiu da janela; se nao bastar, os mais antigos primeiro. */
  private prune(): void {
    const limite = Date.now() - this.maxAgeMs;

    for (const [jti, entrada] of this.cache) {
      if (entrada.checkedAt < limite) this.cache.delete(jti);
    }

    // O Map guarda a ordem de insercao: as primeiras chaves sao as mais velhas.
    while (this.cache.size >= MAX_ENTRIES) {
      const maisVelha = this.cache.keys().next().value;

      if (maisVelha === undefined) break;

      this.cache.delete(maisVelha);
    }
  }
}
