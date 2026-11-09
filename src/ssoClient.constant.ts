export const SSO_CLIENT_OPTIONS = Symbol('SSO_CLIENT_OPTIONS');

export const SSO_TX_COOKIE = 'tx';

export const SSO_SESSION_COOKIE = 'session';

export const TX_COOKIE_TTL_SECONDS = 300;

export const SSO_LEVEL_PUBLIC = 'sso:public';

export const SSO_LEVEL_LOGIN = 'sso:login';

export const SSO_LEVEL_AUTHENTICATED = 'sso:authenticated';

export const SSO_FRESH_GRANT = 'sso:fresh-grant';

export const SSO_CSRF_COOKIE = 'csrf';

export const SSO_CSRF_HEADER = 'x-csrf-token';

export const SSO_SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];
