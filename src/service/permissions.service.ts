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

const MAX_AGE_MS = 60_000;

const REVALIDATE_INTERVAL_MS = 5_000;

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

    const pending = this.inFlight.get(role) ?? this.startFetch(role, key);

    try {
      return await pending;
    } catch (error) {
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
