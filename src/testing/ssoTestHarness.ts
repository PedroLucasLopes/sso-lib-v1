import * as crypto from 'node:crypto';

export interface SqlClient {
  query(
    text: string,
    params?: unknown[],
  ): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
}

export interface SsoTestOptions {
  issuer: string;
  cookieSecret: string;
  selfProjectName?: string;
}

const DEFAULT_SELF_PROJECT = 'SSO';

const CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const NOW = "(now() AT TIME ZONE 'utc')";

const one = async <T = Record<string, unknown>>(
  db: SqlClient,
  sql: string,
  params: unknown[] = [],
): Promise<T | undefined> => (await db.query(sql, params)).rows[0] as T | undefined;

export function sealSsoCookie(cookieSecret: string, payload: unknown): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(cookieSecret, 'hex'),
    iv,
  );

  const sealed = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf8'),
    cipher.final(),
  ]);

  return [
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    sealed.toString('base64url'),
  ].join('.');
}

async function projectByName(
  db: SqlClient,
  name: string,
): Promise<{ id: string; clientId: string }> {
  const project = await one<{ id: string; clientId: string }>(
    db,
    'SELECT id, "clientId" FROM "Project" WHERE name = $1',
    [name],
  );

  if (!project) {
    throw new Error(
      `o projeto "${name}" nao existe no catalogo do SSO; cadastre-o antes de rodar o teste`,
    );
  }

  return project;
}

export async function createSsoSession(
  db: SqlClient,
  options: SsoTestOptions & { userId: string; ttlMinutes?: number },
): Promise<{ sessionId: string; cookie: string }> {
  const sessionId = crypto.randomUUID();
  const minutes = options.ttlMinutes ?? 60;

  await db.query(
    `INSERT INTO "AuthSession" (id, "userId", "expiresAt", "createdAt", "lastSeenAt")
     VALUES ($1, $2, ${NOW} + ($3 || ' minutes')::interval, ${NOW}, ${NOW})`,
    [sessionId, options.userId, String(minutes)],
  );

  return {
    sessionId,
    cookie: `sso_session=${sealSsoCookie(options.cookieSecret, { authSessionId: sessionId })}`,
  };
}

export async function ensureProjectUser(
  db: SqlClient,
  options: {
    projectName: string;
    email: string;
    name?: string;
    role: string;
  },
): Promise<{ userId: string }> {
  const project = await projectByName(db, options.projectName);

  const role = await one<{ id: string }>(
    db,
    'SELECT id FROM "Role" WHERE name = $1 AND "projectId" = $2',
    [options.role, project.id],
  );

  if (!role) {
    throw new Error(
      `o papel ${options.role} nao existe no projeto ${options.projectName}`,
    );
  }

  let user = await one<{ id: string }>(
    db,
    'SELECT id FROM "User" WHERE email = $1',
    [options.email],
  );

  if (!user) {
    user = await one<{ id: string }>(
      db,
      'INSERT INTO "User" (id, email, name) VALUES ($1, $2, $3) RETURNING id',
      [
        crypto.randomUUID(),
        options.email,
        options.name ?? options.email.split('@')[0],
      ],
    );
  }

  await db.query(
    `INSERT INTO "ProjectUser" ("userId", "projectId", "roleId")
     VALUES ($1, $2, $3)
     ON CONFLICT ("userId", "projectId") DO UPDATE SET "roleId" = EXCLUDED."roleId"`,
    [user!.id, project.id, role.id],
  );

  return { userId: user!.id };
}

function clientAssertion(
  clientId: string,
  privateKeyPem: string,
  tokenEndpoint: string,
): string {
  const now = Math.floor(Date.now() / 1000);
  const b64 = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');

  const signingInput = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + 60,
  })}`;

  return `${signingInput}.${crypto
    .sign('sha256', Buffer.from(signingInput), privateKeyPem)
    .toString('base64url')}`;
}

export async function mintAdminToken(
  db: SqlClient,
  options: SsoTestOptions & { email: string },
): Promise<{ token: string; expiresIn: number; role: string; userId: string }> {
  const sso = options.issuer.replace(/\/+$/, '');
  const projectName = options.selfProjectName ?? DEFAULT_SELF_PROJECT;
  const project = await projectByName(db, projectName);

  const redirect = await one<{ redirectUri: string }>(
    db,
    'SELECT "redirectUri" FROM "redirectUri" WHERE "projectId" = $1 ORDER BY "redirectUri" LIMIT 1',
    [project.id],
  );

  if (!redirect) {
    throw new Error(`o projeto ${projectName} nao tem redirect_uri cadastrada`);
  }

  const operator = await one<{ id: string; role: string }>(
    db,
    `SELECT u.id, r.name AS role
       FROM "User" u
       JOIN "ProjectUser" pu ON pu."userId" = u.id AND pu."projectId" = $1
       JOIN "Role" r ON r.id = pu."roleId"
      WHERE u.email = $2`,
    [project.id, options.email],
  );

  if (!operator) {
    throw new Error(`${options.email} nao tem papel no projeto ${projectName}`);
  }

  const pair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const clientKeyId = crypto.randomUUID();
  let sessionId = '';

  const clean = async () => {
    await db.query('DELETE FROM "ClientKey" WHERE id = $1', [clientKeyId]);

    if (sessionId) {
      await db.query('DELETE FROM "RefreshToken" WHERE "authSessionId" = $1', [sessionId]);
      await db.query('DELETE FROM "AuthorizationCode" WHERE "authSessionId" = $1', [sessionId]);
      await db.query('DELETE FROM "AuthSession" WHERE id = $1', [sessionId]);
    }
  };

  try {
    await db.query(
      `INSERT INTO "ClientKey" (id, "projectId", algorithm, "publicKeyPem", "createdAt", "expiresAt")
       VALUES ($1, $2, 'RS256', $3, ${NOW}, ${NOW} + interval '5 minutes')`,
      [clientKeyId, project.id, pair.publicKey],
    );

    const session = await createSsoSession(db, {
      ...options,
      userId: operator.id,
      ttlMinutes: 5,
    });

    sessionId = session.sessionId;

    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto
      .createHash('sha256')
      .update(verifier, 'ascii')
      .digest('base64url');

    const query = new URLSearchParams({
      client_id: project.clientId,
      redirect_uri: redirect.redirectUri,
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: crypto.randomBytes(16).toString('base64url'),
    });

    const authorization = await fetch(`${sso}/oauth/authorize?${query.toString()}`, {
      redirect: 'manual',
      headers: { cookie: session.cookie },
    });

    const local = authorization.headers.get('location');

    if (!local || !local.startsWith(redirect.redirectUri)) {
      throw new Error(
        `authorize nao devolveu o code (HTTP ${authorization.status}, location ${local ?? 'ausente'})`,
      );
    }

    const code = new URL(local).searchParams.get('code');

    if (!code) throw new Error(`authorize devolveu erro: ${local}`);

    const swap = await fetch(`${sso}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        redirect_uri: redirect.redirectUri,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: clientAssertion(
          project.clientId,
          pair.privateKey,
          `${sso}/oauth/token`,
        ),
      }),
    });

    const body = (await swap.json()) as {
      access_token?: string;
      expires_in?: number;
    };

    if (!swap.ok || !body.access_token) {
      throw new Error(
        `token endpoint recusou: HTTP ${swap.status} ${JSON.stringify(body)}`,
      );
    }

    return {
      token: body.access_token,
      expiresIn: body.expires_in ?? 0,
      role: operator.role,
      userId: operator.id,
    };
  } finally {
    await clean().catch(() => undefined);
  }
}

export async function purgeTestUsers(
  db: SqlClient,
  emails: string[],
): Promise<number> {
  if (!emails.length) return 0;

  const { rows } = await db.query(
    'SELECT id FROM "User" WHERE email = ANY($1)',
    [emails],
  );

  const ids = rows.map((line) => line.id as string);

  if (!ids.length) return 0;

  await db.query(
    `DELETE FROM "RefreshToken"
      WHERE "authSessionId" IN (SELECT id FROM "AuthSession" WHERE "userId" = ANY($1))`,
    [ids],
  );
  await db.query(
    `DELETE FROM "AuthorizationCode"
      WHERE "authSessionId" IN (SELECT id FROM "AuthSession" WHERE "userId" = ANY($1))`,
    [ids],
  );
  await db.query('DELETE FROM "AuthSession" WHERE "userId" = ANY($1)', [ids]);
  await db.query('DELETE FROM "ProjectUser" WHERE "userId" = ANY($1)', [ids]);
  await db.query('DELETE FROM "User" WHERE id = ANY($1)', [ids]);

  return ids.length;
}
