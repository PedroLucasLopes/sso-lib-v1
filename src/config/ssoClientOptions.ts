import { ModuleMetadata, Type } from '@nestjs/common';

export interface SsoClientOptions {
  issuer: string;

  internalBaseUrl?: string;

  clientId: string;

  clientPrivateKeyPem: string;

  appBaseUrl: string;

  cookieSecret: string;

  postLoginRedirect?: string;

  loginErrorRedirect?: string;

  cookieSecure?: boolean;

  cookieSameSite?: 'lax' | 'strict' | 'none';

  routePrefix?: string;

  cookiePrefix?: string;

  sessionMaxAgeSeconds?: number;

  refreshSkewSeconds?: number;

  grantCheckSeconds?: number;
}

export interface SsoClientOptionsFactory {
  createSsoClientOptions(): Promise<SsoClientOptions> | SsoClientOptions;
}

export interface SsoClientAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  useFactory?: (
    ...args: never[]
  ) => Promise<SsoClientOptions> | SsoClientOptions;
  inject?: unknown[];
  useClass?: Type<SsoClientOptionsFactory>;
  useExisting?: Type<SsoClientOptionsFactory>;
}
