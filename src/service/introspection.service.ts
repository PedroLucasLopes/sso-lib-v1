import { Inject, Injectable, Logger } from '@nestjs/common';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import {
  CLIENT_ASSERTION_TYPE,
  SsoClientAssertionService,
} from './clientAssertion.service';
import { SsoDiscoveryService } from './discovery.service';

export interface SsoGrantState {
  active: boolean;
  roles?: string[];
  perm?: string;
}

interface CachedState {
  state: SsoGrantState;
  checkedAt: number;
}

const DEFAULT_CHECK_SECONDS = 30;

const MAX_ENTRIES = 5_000;

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

    const pending =
      this.inFlight.get(jti) ?? this.start(token, jti, cached ?? null);

    return pending;
  }

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

        const inactive: SsoGrantState = { active: false };

        this.store(jti, inactive);

        return inactive;
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

  private prune(): void {
    const limit = Date.now() - this.maxAgeMs;

    for (const [jti, entry] of this.cache) {
      if (entry.checkedAt < limit) this.cache.delete(jti);
    }

    while (this.cache.size >= MAX_ENTRIES) {
      const oldest = this.cache.keys().next().value;

      if (oldest === undefined) break;

      this.cache.delete(oldest);
    }
  }
}
