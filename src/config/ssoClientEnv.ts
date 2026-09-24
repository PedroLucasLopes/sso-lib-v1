import { loadPrivateKeyPem } from './privateKeySource';
import type { SsoClientOptions } from './ssoClientOptions';

type Environment = Readonly<Record<string, string | undefined>>;

const SAME_SITE_VALUES = ['lax', 'strict', 'none'];

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

  const grantCheck = read('APP_GRANT_CHECK_SECONDS');
  const grantCheckSeconds =
    grantCheck === undefined ? undefined : Number(grantCheck);

  if (
    grantCheckSeconds !== undefined &&
    !(Number.isInteger(grantCheckSeconds) && grantCheckSeconds >= 0)
  ) {
    problems.push(
      'APP_GRANT_CHECK_SECONDS precisa ser um numero inteiro de segundos, 0 ou mais',
    );
  }

  const loginErrorRedirect = read('APP_LOGIN_ERROR_REDIRECT');

  if (loginErrorRedirect !== undefined && !isRedirectTarget(loginErrorRedirect)) {
    problems.push(
      'APP_LOGIN_ERROR_REDIRECT invalida: use um caminho, como /sign-in-error, ou uma URL http(s)',
    );
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
    loginErrorRedirect,
    cookiePrefix: read('APP_COOKIE_PREFIX'),
    routePrefix: read('APP_ROUTE_PREFIX'),
    cookieSecure: read('COOKIE_SECURE') !== 'false',
    cookieSameSite: sameSite as SsoClientOptions['cookieSameSite'],
    sessionMaxAgeSeconds,
    grantCheckSeconds,
    ...explicit,
  };
}

function isRedirectTarget(value: string): boolean {
  if (value.startsWith('/')) return !/^\/[/\\]/.test(value);

  try {
    return ['http:', 'https:'].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}
