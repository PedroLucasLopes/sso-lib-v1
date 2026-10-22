import { Logger } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import {
  CLIENT_ASSERTION_TYPE,
  SsoClientAssertionService,
} from './clientAssertion.service';
import {
  SsoDeletedAccountsService,
  type SsoDeletedAccountsPage,
} from './deletedAccounts.service';
import { SsoDiscoveryService } from './discovery.service';

const CLIENT_ID = 'meetme-test';
const PUBLIC_ISSUER = 'https://sso.example.test/sso';
const TOKEN_ENDPOINT = `${PUBLIC_ISSUER}/oauth/token`;
const FEED_PATH = '/sso/oauth/deleted-accounts';

function rsaKeys(): { privateKey: string; publicKey: string } {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
}

const registered = rsaKeys();

interface FeedRequest {
  after?: unknown;
  client_id?: unknown;
  client_assertion_type?: unknown;
  client_assertion?: unknown;
}

interface Reply {
  status: number;
  body: unknown;
}

function decodePart(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
}

function acceptedAssertion(request: FeedRequest): boolean {
  if (
    request.client_id !== CLIENT_ID ||
    request.client_assertion_type !== CLIENT_ASSERTION_TYPE ||
    typeof request.client_assertion !== 'string'
  ) {
    return false;
  }

  const [header, payload, signature] = request.client_assertion.split('.');

  if (!header || !payload || !signature) return false;

  const signed = crypto.verify(
    'sha256',
    Buffer.from(`${header}.${payload}`),
    registered.publicKey,
    Buffer.from(signature, 'base64url'),
  );

  if (!signed) return false;

  const claims = decodePart(payload);
  const now = Math.floor(Date.now() / 1000);

  return (
    decodePart(header).alg === 'RS256' &&
    claims.iss === CLIENT_ID &&
    claims.sub === CLIENT_ID &&
    claims.aud === TOKEN_ENDPOINT &&
    typeof claims.jti === 'string' &&
    typeof claims.exp === 'number' &&
    claims.exp > now &&
    claims.exp - now <= 300
  );
}

class FakeSso {
  readonly requests: FeedRequest[] = [];
  readonly replies: Reply[] = [];
  announcesFeed = true;

  private readonly server = createServer((req, res) => {
    const chunks: Buffer[] = [];

    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const reply = this.answer(
        `${req.method} ${req.url}`,
        Buffer.concat(chunks).toString('utf8'),
      );

      res.writeHead(reply.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(reply.body));
    });
  });

  async start(): Promise<string> {
    await new Promise<void>((resolve) => {
      this.server.listen(0, '127.0.0.1', resolve);
    });

    const { port } = this.server.address() as AddressInfo;

    return `http://127.0.0.1:${port}/sso`;
  }

  stop(): Promise<void> {
    this.server.closeAllConnections();

    return new Promise((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  reset(): void {
    this.requests.length = 0;
    this.replies.length = 0;
    this.announcesFeed = true;
  }

  private answer(route: string, text: string): Reply {
    if (route === 'GET /sso/.well-known/oauth-authorization-server') {
      return {
        status: 200,
        body: {
          issuer: PUBLIC_ISSUER,
          authorization_endpoint: `${PUBLIC_ISSUER}/oauth/authorize`,
          token_endpoint: TOKEN_ENDPOINT,
          jwks_uri: `${PUBLIC_ISSUER}/.well-known/jwks.json`,
          ...(this.announcesFeed
            ? { deleted_accounts_endpoint: `${PUBLIC_ISSUER}/oauth/deleted-accounts` }
            : {}),
        },
      };
    }

    if (route !== `POST ${FEED_PATH}`) return { status: 404, body: {} };

    const request = JSON.parse(text) as FeedRequest;

    this.requests.push(request);

    if (!acceptedAssertion(request)) {
      return {
        status: 401,
        body: {
          error: 'invalid_client',
          error_description: 'asserção de cliente invalida',
        },
      };
    }

    return (
      this.replies.shift() ?? {
        status: 200,
        body: { accounts: [], cursor: request.after ?? null, has_more: false },
      }
    );
  }
}

function feedPage(
  subs: string[],
  cursor: string | null,
  hasMore: boolean,
): Reply {
  return {
    status: 200,
    body: {
      accounts: subs.map((sub, index) => ({
        sub,
        deleted_at: new Date(Date.UTC(2026, 9, 22, 12, index)).toISOString(),
      })),
      cursor,
      has_more: hasMore,
    },
  };
}

async function collect(
  pages: AsyncIterable<SsoDeletedAccountsPage>,
): Promise<SsoDeletedAccountsPage[]> {
  const collected: SsoDeletedAccountsPage[] = [];

  for await (const page of pages) collected.push(page);

  return collected;
}

describe('SsoDeletedAccountsService', () => {
  const sso = new FakeSso();
  let internalBaseUrl = '';

  function feed(privateKeyPem = registered.privateKey): SsoDeletedAccountsService {
    const options: SsoClientOptions = {
      issuer: PUBLIC_ISSUER,
      internalBaseUrl,
      clientId: CLIENT_ID,
      clientPrivateKeyPem: privateKeyPem,
      appBaseUrl: 'https://app.example.test/api',
      cookieSecret: '0'.repeat(64),
    };
    const discovery = new SsoDiscoveryService(options);

    return new SsoDeletedAccountsService(
      options,
      discovery,
      new SsoClientAssertionService(options, discovery),
    );
  }

  beforeAll(async () => {
    Logger.overrideLogger(false);
    internalBaseUrl = await sso.start();
  });

  afterEach(() => {
    sso.reset();
  });

  afterAll(() => sso.stop());

  it('reads a page at the internal address, authenticated by the client assertion of the token endpoint', async () => {
    sso.replies.push(feedPage(['sub-1', 'sub-2'], 'cursor-1', false));

    const page = await feed().page();

    expect(page).toEqual({
      accounts: [
        { sub: 'sub-1', deletedAt: new Date('2026-10-22T12:00:00.000Z') },
        { sub: 'sub-2', deletedAt: new Date('2026-10-22T12:01:00.000Z') },
      ],
      cursor: 'cursor-1',
      hasMore: false,
    });
    expect(sso.requests).toHaveLength(1);
    expect(sso.requests[0]).not.toHaveProperty('after');
  });

  it('sends the stored cursor back as after', async () => {
    await feed().page('cursor-7');

    expect(sso.requests[0]?.after).toBe('cursor-7');
  });

  it('pages until has_more is false, passing each cursor back', async () => {
    sso.replies.push(
      feedPage(['sub-1', 'sub-2'], 'cursor-1', true),
      feedPage(['sub-3', 'sub-4'], 'cursor-2', true),
      feedPage(['sub-5'], 'cursor-3', false),
    );

    const pages = await collect(feed().pages());

    expect(pages.map((page) => page.accounts.map((account) => account.sub))).toEqual([
      ['sub-1', 'sub-2'],
      ['sub-3', 'sub-4'],
      ['sub-5'],
    ]);
    expect(pages.map((page) => page.cursor)).toEqual([
      'cursor-1',
      'cursor-2',
      'cursor-3',
    ]);
    expect(sso.requests.map((request) => request.after)).toEqual([
      undefined,
      'cursor-1',
      'cursor-2',
    ]);
  });

  it('starts from a stored cursor and keeps it when nothing new was deleted', async () => {
    const pages = await collect(feed().pages('cursor-9'));

    expect(pages).toEqual([{ accounts: [], cursor: 'cursor-9', hasMore: false }]);
    expect(sso.requests.map((request) => request.after)).toEqual(['cursor-9']);
  });

  it('answers an empty feed with no cursor when nothing was ever deleted', async () => {
    const pages = await collect(feed().pages(null));

    expect(pages).toEqual([{ accounts: [], cursor: null, hasMore: false }]);
    expect(sso.requests[0]).not.toHaveProperty('after');
  });

  it('refuses when the SSO does not announce the feed, without calling it', async () => {
    sso.announcesFeed = false;

    await expect(feed().page()).rejects.toThrow('deleted_accounts_endpoint');
    expect(sso.requests).toHaveLength(0);
  });

  it('surfaces the OAuth error when the SSO does not accept the client key', async () => {
    await expect(feed(rsaKeys().privateKey).page()).rejects.toThrow(
      /invalid_client/,
    );
    expect(sso.requests).toHaveLength(1);
  });

  it('surfaces the OAuth error when the SSO refuses the cursor', async () => {
    sso.replies.push({
      status: 400,
      body: {
        error: 'invalid_request',
        error_description: 'after deve ser o cursor devolvido pela propria lista',
      },
    });

    await expect(feed().page('forged')).rejects.toThrow(/invalid_request/);
  });

  it('refuses a malformed answer instead of skipping accounts', async () => {
    sso.replies.push({
      status: 200,
      body: { accounts: [{ sub: 42 }], cursor: 'cursor-1', has_more: false },
    });

    await expect(feed().page()).rejects.toThrow(/fora do formato/);
  });

  it('stops instead of looping when the SSO claims more pages without moving the cursor', async () => {
    sso.replies.push(feedPage(['sub-1'], 'cursor-1', true), feedPage([], 'cursor-1', true));

    await expect(collect(feed().pages())).rejects.toThrow(/sem avancar o cursor/);
    expect(sso.requests).toHaveLength(2);
  });
});
