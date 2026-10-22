import { Inject, Injectable } from '@nestjs/common';
import { SSO_CLIENT_OPTIONS } from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import {
  CLIENT_ASSERTION_TYPE,
  SsoClientAssertionService,
} from './clientAssertion.service';
import { SsoDiscoveryService } from './discovery.service';

export interface SsoDeletedAccount {
  sub: string;
  deletedAt: Date;
}

export interface SsoDeletedAccountsPage {
  accounts: SsoDeletedAccount[];
  cursor: string | null;
  hasMore: boolean;
}

interface FeedResponse {
  accounts?: unknown;
  cursor?: unknown;
  has_more?: unknown;
  error?: unknown;
  error_description?: unknown;
}

@Injectable()
export class SsoDeletedAccountsService {
  private readonly clientId: string;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private discovery: SsoDiscoveryService,
    private assertions: SsoClientAssertionService,
  ) {
    this.clientId = options.clientId;
  }

  async *pages(
    after?: string | null,
  ): AsyncGenerator<SsoDeletedAccountsPage, void, undefined> {
    let cursor = after ?? null;

    for (;;) {
      const page = await this.page(cursor);

      yield page;

      if (!page.hasMore) return;

      if (!page.cursor || page.cursor === cursor) {
        throw new Error(
          'o SSO anunciou mais contas excluidas sem avancar o cursor',
        );
      }

      cursor = page.cursor;
    }
  }

  async page(after?: string | null): Promise<SsoDeletedAccountsPage> {
    const { deleted_accounts_endpoint: endpoint } =
      await this.discovery.metadata();

    if (!endpoint) {
      throw new Error('o SSO nao anuncia deleted_accounts_endpoint');
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...(after ? { after } : {}),
        client_id: this.clientId,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await this.assertions.build(),
      }),
    });

    const body = (await res.json().catch(() => null)) as FeedResponse | null;

    if (!res.ok) {
      const detail =
        typeof body?.error === 'string'
          ? `${body.error}: ${typeof body.error_description === 'string' ? body.error_description : ''}`.trim()
          : `HTTP ${res.status}`;

      throw new Error(`o SSO recusou a lista de contas excluidas (${detail})`);
    }

    const page = body ? toPage(body) : null;

    if (!page) {
      throw new Error(
        'resposta do SSO fora do formato da lista de contas excluidas',
      );
    }

    return page;
  }
}

function toPage(body: FeedResponse): SsoDeletedAccountsPage | null {
  const { accounts, cursor, has_more: hasMore } = body;

  if (!Array.isArray(accounts) || typeof hasMore !== 'boolean') return null;

  if (cursor !== null && typeof cursor !== 'string') return null;

  const parsed: SsoDeletedAccount[] = [];

  for (const entry of accounts as unknown[]) {
    const { sub, deleted_at: deletedAt } = (entry ?? {}) as {
      sub?: unknown;
      deleted_at?: unknown;
    };
    const at = typeof deletedAt === 'string' ? new Date(deletedAt) : null;

    if (typeof sub !== 'string' || !sub || !at || Number.isNaN(at.getTime())) {
      return null;
    }

    parsed.push({ sub, deletedAt: at });
  }

  return { accounts: parsed, cursor, hasMore };
}
