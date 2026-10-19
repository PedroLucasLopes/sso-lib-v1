import { NestFactory } from '@nestjs/core';
import type { INestApplication } from '@nestjs/common';
import * as crypto from 'node:crypto';
import * as net from 'node:net';
import type { AddressInfo } from 'node:net';
import { AppModule } from './app.module';

const PREFIX = 'api';

const BOOT =
  'sobe com SsoClientModule.forRoot, issuer ficticio e chave gerada na hora';

interface Seen {
  status: number;
  location: string | null;
  setsCookie: boolean;
  body: Record<string, unknown>;
}

let passed = 0;
let failed = 0;

function check(name: string, ok: boolean, detail: string): void {
  if (ok) {
    passed += 1;
  } else {
    failed += 1;
  }

  console.log(
    `${ok ? '  OK  ' : ' FALHA'} | ${name}${ok ? '' : ` -> ${detail}`}`,
  );
}

function describe(seen: Seen): string {
  return [
    `HTTP ${seen.status}`,
    seen.location ? `Location ${seen.location}` : '',
    seen.setsCookie ? 'com Set-Cookie' : '',
    JSON.stringify(seen.body),
  ]
    .filter(Boolean)
    .join(', ');
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();

    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;

      server.close(() => resolve(port));
    });
  });
}

async function request(
  url: string,
  headers: Record<string, string> = {},
): Promise<Seen> {
  const res = await fetch(url, { headers, redirect: 'manual' });
  const text = await res.text();

  let body: Record<string, unknown> = {};

  try {
    body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    body = { text };
  }

  return {
    status: res.status,
    location: res.headers.get('location'),
    setsCookie: res.headers.has('set-cookie'),
    body,
  };
}

async function boot(
  port: number,
  appBaseUrl: string,
): Promise<INestApplication> {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const app = await NestFactory.create(
    AppModule.register({
      issuer: 'https://sso.invalid/sso',
      clientId: 'nest12-smoke',
      clientPrivateKeyPem: privateKey,
      appBaseUrl,
      cookieSecret: crypto.randomBytes(32).toString('hex'),
      cookieSecure: false,
      cookiePrefix: 'smoke',
    }),
    { logger: ['error'], abortOnError: false },
  );

  app.setGlobalPrefix(PREFIX);
  await app.listen(port, '127.0.0.1');

  return app;
}

async function probe(appBaseUrl: string): Promise<void> {
  const jar = await request(`${appBaseUrl}/public/cookies`, {
    cookie: 'smoke_probe=nest12',
  });
  const cookies = jar.body.cookies as Record<string, unknown> | null;

  check(
    'cookie-parser em {*splat}: req.cookies lido na rota @SsoPublic()',
    jar.status === 200 && cookies?.smoke_probe === 'nest12',
    describe(jar),
  );

  const anonymous = await request(`${appBaseUrl}/optional`);

  check(
    '@SsoOptional() sem credencial: 200, sem usuario e sem Set-Cookie',
    anonymous.status === 200 &&
      anonymous.body.user === null &&
      anonymous.body.token === null &&
      !anonymous.setsCookie,
    describe(anonymous),
  );

  const malformed = await request(`${appBaseUrl}/optional`, {
    authorization: 'Bearer nao-e-um-jwt',
  });

  check(
    '@SsoOptional() com Bearer malformado: 401 invalid_token',
    malformed.status === 401 && malformed.body.error === 'invalid_token',
    describe(malformed),
  );

  const api = await request(`${appBaseUrl}/private`, {
    accept: 'application/json',
  });
  const loginUrl = api.body.login_url;

  check(
    '@SsoAuthenticated() sem credencial, chamada de API: 401 login_required',
    api.status === 401 &&
      api.body.error === 'login_required' &&
      typeof loginUrl === 'string' &&
      loginUrl.startsWith(`${appBaseUrl}/auth/login?returnTo=`),
    describe(api),
  );

  const page = await request(`${appBaseUrl}/private`, {
    'sec-fetch-dest': 'document',
  });

  check(
    '@SsoAuthenticated() sem credencial, navegacao de pagina: 302 para /auth/login',
    page.status === 302 &&
      page.location ===
        `${appBaseUrl}/auth/login?returnTo=${encodeURIComponent(`/${PREFIX}/private`)}`,
    describe(page),
  );

  const visitor = await request(`${appBaseUrl}/visitor`);

  check(
    '@SsoOptional() na classe: 200 sem credencial e sem usuario',
    visitor.status === 200 && visitor.body.user === null,
    describe(visitor),
  );
}

async function main(): Promise<void> {
  const port = await freePort();
  const appBaseUrl = `http://127.0.0.1:${port}/${PREFIX}`;

  let app: INestApplication;

  try {
    app = await boot(port, appBaseUrl);
  } catch (error) {
    check(BOOT, false, error instanceof Error ? error.message : String(error));
    return;
  }

  check(BOOT, true, '');

  try {
    await probe(appBaseUrl);
  } finally {
    await app.close();
  }
}

main()
  .catch((error: unknown) => {
    check(
      'o smoke roda ate o fim',
      false,
      error instanceof Error ? (error.stack ?? error.message) : String(error),
    );
  })
  .finally(() => {
    console.log(`\n${passed} passaram, ${failed} falharam`);
    process.exitCode = failed === 0 && passed > 0 ? 0 : 1;
  });
