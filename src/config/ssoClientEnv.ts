import { loadPrivateKeyPem } from './privateKeySource';
import type { SsoClientOptions } from './ssoClientOptions';

type Environment = Readonly<Record<string, string | undefined>>;

const SAME_SITE_VALUES = ['lax', 'strict', 'none'];

/**
 * Monta as opcoes do modulo a partir das variaveis de ambiente do ecossistema.
 *
 * E o caminho curto para uma API nova. Os nomes sao os mesmos em toda
 * aplicacao ligada ao SSO, entao o `.env` de uma serve de modelo para a outra,
 * e o `app.module.ts` fica com uma linha: `SsoClientModule.forRootFromEnv()`.
 *
 * | Variavel | Obrigatoria | Vira |
 * |---|---|---|
 * | `SSO_ISSUER` | sim | `issuer` |
 * | `APP_CLIENT_ID` | sim | `clientId` |
 * | `APP_BASE_URL` | sim | `appBaseUrl` |
 * | `COOKIE_SECRET` | sim | `cookieSecret` |
 * | `APP_PRIVATE_KEY_FILE`, `APP_PRIVATE_KEY_BASE64` ou `APP_PRIVATE_KEY` | uma delas | `clientPrivateKeyPem` |
 * | `SSO_INTERNAL_URL` | nao | `internalBaseUrl` |
 * | `APP_POST_LOGIN_REDIRECT` | nao | `postLoginRedirect` |
 * | `APP_COOKIE_PREFIX` | nao | `cookiePrefix` |
 * | `APP_ROUTE_PREFIX` | nao | `routePrefix` |
 * | `APP_SESSION_MAX_AGE` | nao | `sessionMaxAgeSeconds` |
 * | `COOKIE_SECURE` | nao | `cookieSecure`; so `false` desliga |
 * | `COOKIE_SAMESITE` | nao | `cookieSameSite` |
 *
 * **Tudo o que falta aparece de uma vez.** Configuracao incompleta derruba o
 * boot com a lista inteira, e nao uma variavel por vez: descobrir a terceira
 * so depois de corrigir a segunda e o que transforma configuracao em tarde
 * perdida. A mensagem cita nomes, nunca valores, porque metade deles e segredo.
 *
 * `overrides` ganha do ambiente, para o que a aplicacao preferir fixar no
 * codigo. Chave com `undefined` e ignorada, e nao apaga o que veio do ambiente.
 */
export function ssoClientOptionsFromEnv(
  env: Environment = process.env,
  overrides: Partial<SsoClientOptions> = {},
): SsoClientOptions {
  const read = (name: string): string | undefined => {
    const value = env[name]?.trim();

    return value ? value : undefined;
  };

  const problems: string[] = [];

  const required = (name: string, override: string | undefined): string => {
    const value = override ?? read(name);

    if (!value) {
      problems.push(`${name} nao definida`);
    }

    return value ?? '';
  };

  const issuer = required('SSO_ISSUER', overrides.issuer);
  const clientId = required('APP_CLIENT_ID', overrides.clientId);
  const appBaseUrl = required('APP_BASE_URL', overrides.appBaseUrl);
  const cookieSecret = required('COOKIE_SECRET', overrides.cookieSecret);

  let clientPrivateKeyPem = overrides.clientPrivateKeyPem ?? '';

  if (!clientPrivateKeyPem) {
    const source = {
      file: read('APP_PRIVATE_KEY_FILE'),
      base64: read('APP_PRIVATE_KEY_BASE64'),
      pem: read('APP_PRIVATE_KEY'),
    };

    if (!source.file && !source.base64 && !source.pem) {
      problems.push(
        'chave privada nao definida: use APP_PRIVATE_KEY_FILE, APP_PRIVATE_KEY_BASE64 ou APP_PRIVATE_KEY',
      );
    } else {
      try {
        clientPrivateKeyPem = loadPrivateKeyPem(source);
      } catch (error) {
        problems.push(error instanceof Error ? error.message : String(error));
      }
    }
  }

  const sameSite = read('COOKIE_SAMESITE')?.toLowerCase();

  if (sameSite !== undefined && !SAME_SITE_VALUES.includes(sameSite)) {
    problems.push('COOKIE_SAMESITE invalida: use lax, strict ou none');
  }

  const maxAge = read('APP_SESSION_MAX_AGE');
  const sessionMaxAgeSeconds = maxAge === undefined ? undefined : Number(maxAge);

  if (
    sessionMaxAgeSeconds !== undefined &&
    !(Number.isInteger(sessionMaxAgeSeconds) && sessionMaxAgeSeconds > 0)
  ) {
    problems.push('APP_SESSION_MAX_AGE precisa ser um numero inteiro de segundos');
  }

  if (problems.length > 0) {
    throw new Error(
      `@pedrolucaslopes/sso-client: configuracao incompleta\n${problems
        .map((problem) => `  - ${problem}`)
        .join('\n')}`,
    );
  }

  const explicit = Object.fromEntries(
    Object.entries(overrides).filter(([, value]) => value !== undefined),
  ) as Partial<SsoClientOptions>;

  return {
    issuer,
    clientId,
    clientPrivateKeyPem,
    appBaseUrl,
    cookieSecret,
    internalBaseUrl: read('SSO_INTERNAL_URL'),
    postLoginRedirect: read('APP_POST_LOGIN_REDIRECT'),
    cookiePrefix: read('APP_COOKIE_PREFIX'),
    routePrefix: read('APP_ROUTE_PREFIX'),
    // Seguro por padrao: so `false` explicito desliga, e so faz sentido em
    // desenvolvimento sobre HTTP.
    cookieSecure: read('COOKIE_SECURE') !== 'false',
    cookieSameSite: sameSite as SsoClientOptions['cookieSameSite'],
    sessionMaxAgeSeconds,
    ...explicit,
  };
}
