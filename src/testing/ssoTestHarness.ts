import * as crypto from 'node:crypto';

/**
 * Ferramentas para uma aplicacao testar a si mesma contra um SSO de verdade.
 *
 * Existe aqui, e nao no repositorio do SSO, por uma razao de arquitetura: cada
 * aplicacao do ecossistema e independente, com repositorio, infraestrutura e
 * ciclo de vida proprios. Se o teste de uma delas precisasse importar codigo de
 * dentro do SSO, a independencia seria de fachada. Este pacote ja e o contrato
 * entre o SSO e quem se conecta a ele, entao e ele que viaja junto.
 *
 * ⚠️ **Nada disto e para producao.** Tudo aqui pressupoe credenciais de
 * OPERADOR do SSO: a string de conexao do banco e a `COOKIE_SECRET`. Sao as
 * mesmas credenciais que quem administra o ambiente de desenvolvimento ja tem.
 * Um ambiente onde a aplicacao nao deveria ter isso e um ambiente onde estes
 * helpers nao rodam, e e assim mesmo que deve ser.
 *
 * O que eles substituem: o login federado no provedor de identidade, que um
 * teste automatizado nao tem como fazer. O resto do caminho e real.
 */

/** Cliente SQL minimo. Evita depender de `pg` aqui: quem chama traz o dele. */
export interface SqlClient {
  query(
    text: string,
    params?: unknown[],
  ): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
}

export interface SsoTestOptions {
  /** Identidade publica do SSO, com prefixo. Ex.: `http://localhost:8080/sso`. */
  issuer: string;
  /** `COOKIE_SECRET` do SSO, em hex. E com ela que a sessao e selada. */
  cookieSecret: string;
  /** Nome do `Project` que representa o proprio SSO no catalogo dele. */
  selfProjectName?: string;
}

const SELF_PROJECT_PADRAO = 'SSO';

const CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/**
 * Carimbo em UTC.
 *
 * O Prisma grava e le `DateTime` como UTC, e o `now()` do Postgres devolve a
 * hora local do servidor. Num banco fora de UTC, `now()` cru faz a linha nascer
 * no passado, e a sessao ja aparece expirada para o servidor.
 */
const AGORA = "(now() AT TIME ZONE 'utc')";

const uma = async <T = Record<string, unknown>>(
  db: SqlClient,
  sql: string,
  params: unknown[] = [],
): Promise<T | undefined> => (await db.query(sql, params)).rows[0] as T | undefined;

/** Sela um valor no mesmo formato do `CookieService`: AES-256-GCM, `iv.tag.texto`. */
export function sealSsoCookie(cookieSecret: string, payload: unknown): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(cookieSecret, 'hex'),
    iv,
  );

  const texto = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf8'),
    cipher.final(),
  ]);

  return [
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    texto.toString('base64url'),
  ].join('.');
}

async function projetoPorNome(
  db: SqlClient,
  nome: string,
): Promise<{ id: string; clientId: string }> {
  const projeto = await uma<{ id: string; clientId: string }>(
    db,
    'SELECT id, "clientId" FROM "Project" WHERE name = $1',
    [nome],
  );

  if (!projeto) {
    throw new Error(
      `o projeto "${nome}" nao existe no catalogo do SSO; cadastre-o antes de rodar o teste`,
    );
  }

  return projeto;
}

/**
 * Cria uma sessao do usuario com o SSO e devolve o cookie pronto.
 *
 * E o que substitui o login no provedor federado. A partir daqui o fluxo e
 * real: `/authorize` ve a sessao viva e emite o code na hora.
 */
export async function createSsoSession(
  db: SqlClient,
  options: SsoTestOptions & { userId: string; ttlMinutes?: number },
): Promise<{ sessionId: string; cookie: string }> {
  const sessionId = crypto.randomUUID();
  const minutos = options.ttlMinutes ?? 60;

  await db.query(
    `INSERT INTO "AuthSession" (id, "userId", "expiresAt", "createdAt", "lastSeenAt")
     VALUES ($1, $2, ${AGORA} + ($3 || ' minutes')::interval, ${AGORA}, ${AGORA})`,
    [sessionId, options.userId, String(minutos)],
  );

  return {
    sessionId,
    cookie: `sso_session=${sealSsoCookie(options.cookieSecret, { authSessionId: sessionId })}`,
  };
}

/** Garante que um usuario existe e tem `role` no projeto indicado. */
export async function ensureProjectUser(
  db: SqlClient,
  options: {
    projectName: string;
    email: string;
    name?: string;
    role: string;
  },
): Promise<{ userId: string }> {
  const projeto = await projetoPorNome(db, options.projectName);

  const papel = await uma<{ id: string }>(
    db,
    'SELECT id FROM "Role" WHERE name = $1::"RoleEnum" AND "projectId" = $2',
    [options.role, projeto.id],
  );

  if (!papel) {
    throw new Error(
      `o papel ${options.role} nao existe no projeto ${options.projectName}`,
    );
  }

  let usuario = await uma<{ id: string }>(
    db,
    'SELECT id FROM "User" WHERE email = $1',
    [options.email],
  );

  if (!usuario) {
    usuario = await uma<{ id: string }>(
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
    [usuario!.id, projeto.id, papel.id],
  );

  return { userId: usuario!.id };
}

/** Asercao de cliente do `private_key_jwt` (RFC 7523 secao 2.2). */
function clientAssertion(
  clientId: string,
  privateKeyPem: string,
  tokenEndpoint: string,
): string {
  const agora = Math.floor(Date.now() / 1000);
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString('base64url');

  const entrada = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    jti: crypto.randomUUID(),
    iat: agora,
    exp: agora + 60,
  })}`;

  return `${entrada}.${crypto
    .sign('sha256', Buffer.from(entrada), privateKeyPem)
    .toString('base64url')}`;
}

/**
 * Emite um access token administrativo percorrendo o fluxo OAuth inteiro.
 *
 * Serve ao teste que precisa cadastrar rota, papel ou usuario no SSO antes de
 * exercitar a propria aplicacao. Nao contorna autorizacao: o token sai com o
 * `sub` da pessoa e com o papel que ela tem em `ProjectUser`. Quem nao
 * administra recebe um token que nao abre nada.
 *
 * A chave de cliente efemera e a sessao usadas no caminho sao desfeitas antes
 * de retornar.
 */
export async function mintAdminToken(
  db: SqlClient,
  options: SsoTestOptions & { email: string },
): Promise<{ token: string; expiresIn: number; role: string; userId: string }> {
  const sso = options.issuer.replace(/\/+$/, '');
  const nomeDoProjeto = options.selfProjectName ?? SELF_PROJECT_PADRAO;
  const projeto = await projetoPorNome(db, nomeDoProjeto);

  const redirect = await uma<{ redirectUri: string }>(
    db,
    'SELECT "redirectUri" FROM "redirectUri" WHERE "projectId" = $1 ORDER BY "redirectUri" LIMIT 1',
    [projeto.id],
  );

  if (!redirect) {
    throw new Error(`o projeto ${nomeDoProjeto} nao tem redirect_uri cadastrada`);
  }

  const operador = await uma<{ id: string; papel: string }>(
    db,
    `SELECT u.id, r.name AS papel
       FROM "User" u
       JOIN "ProjectUser" pu ON pu."userId" = u.id AND pu."projectId" = $1
       JOIN "Role" r ON r.id = pu."roleId"
      WHERE u.email = $2`,
    [projeto.id, options.email],
  );

  if (!operador) {
    throw new Error(`${options.email} nao tem papel no projeto ${nomeDoProjeto}`);
  }

  const par = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const clientKeyId = crypto.randomUUID();
  let sessionId = '';

  const limpar = async () => {
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
       VALUES ($1, $2, 'RS256', $3, ${AGORA}, ${AGORA} + interval '5 minutes')`,
      [clientKeyId, projeto.id, par.publicKey],
    );

    const sessao = await createSsoSession(db, {
      ...options,
      userId: operador.id,
      ttlMinutes: 5,
    });

    sessionId = sessao.sessionId;

    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto
      .createHash('sha256')
      .update(verifier, 'ascii')
      .digest('base64url');

    const query = new URLSearchParams({
      client_id: projeto.clientId,
      redirect_uri: redirect.redirectUri,
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: crypto.randomBytes(16).toString('base64url'),
    });

    const autorizacao = await fetch(`${sso}/oauth/authorize?${query.toString()}`, {
      redirect: 'manual',
      headers: { cookie: sessao.cookie },
    });

    const local = autorizacao.headers.get('location');

    if (!local || !local.startsWith(redirect.redirectUri)) {
      throw new Error(
        `authorize nao devolveu o code (HTTP ${autorizacao.status}, location ${local ?? 'ausente'})`,
      );
    }

    const code = new URL(local).searchParams.get('code');

    if (!code) throw new Error(`authorize devolveu erro: ${local}`);

    const troca = await fetch(`${sso}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        redirect_uri: redirect.redirectUri,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: clientAssertion(
          projeto.clientId,
          par.privateKey,
          `${sso}/oauth/token`,
        ),
      }),
    });

    const corpo = (await troca.json()) as {
      access_token?: string;
      expires_in?: number;
    };

    if (!troca.ok || !corpo.access_token) {
      throw new Error(
        `token endpoint recusou: HTTP ${troca.status} ${JSON.stringify(corpo)}`,
      );
    }

    return {
      token: corpo.access_token,
      expiresIn: corpo.expires_in ?? 0,
      role: operador.papel,
      userId: operador.id,
    };
  } finally {
    await limpar().catch(() => undefined);
  }
}

/**
 * Apaga do SSO o que uma rodada de teste criou.
 *
 * Por e-mail exato, nunca por padrao: limpeza com curinga e limpeza que um dia
 * apaga dado real. A ordem das tabelas segue as chaves estrangeiras.
 */
export async function purgeTestUsers(
  db: SqlClient,
  emails: string[],
): Promise<number> {
  if (!emails.length) return 0;

  const { rows } = await db.query(
    'SELECT id FROM "User" WHERE email = ANY($1)',
    [emails],
  );

  const ids = rows.map((linha) => linha.id as string);

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
