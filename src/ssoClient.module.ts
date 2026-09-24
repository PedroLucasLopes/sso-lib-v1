import {
  DynamicModule,
  MiddlewareConsumer,
  Module,
  NestModule,
  Provider,
  RequestMethod,
} from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { SSO_CLIENT_OPTIONS } from './ssoClient.constant';
import { ssoClientOptionsFromEnv } from './config/ssoClientEnv';
import type {
  SsoClientAsyncOptions,
  SsoClientOptions,
} from './config/ssoClientOptions';
import { SsoCookieService } from './cookie/cookie.service';
import { SsoAuthController } from './controller/ssoAuth.controller';
import { SsoLoginRequiredFilter } from './error/loginRequired.filter';
import { SsoRbacGuard } from './guard/ssoRbac.guard';
import { SsoClientAssertionService } from './service/clientAssertion.service';
import { SsoDiscoveryService } from './service/discovery.service';
import { SsoIntrospectionService } from './service/introspection.service';
import { SsoJwksVerifierService } from './service/jwksVerifier.service';
import { SsoPermissionsService } from './service/permissions.service';
import { SsoOAuthService } from './service/ssoOAuth.service';
import { SsoSessionService } from './service/ssoSession.service';

const services: Provider[] = [
  SsoCookieService,
  SsoDiscoveryService,
  SsoJwksVerifierService,
  SsoClientAssertionService,
  SsoPermissionsService,
  SsoIntrospectionService,
  SsoSessionService,
  SsoOAuthService,
];

@Module({})
export class SsoClientModule implements NestModule {
  static forRoot(options: SsoClientOptions): DynamicModule {
    return this.build({
      provide: SSO_CLIENT_OPTIONS,
      useValue: options,
    });
  }

  static forRootFromEnv(
    overrides: Partial<SsoClientOptions> = {},
  ): DynamicModule {
    return this.build({
      provide: SSO_CLIENT_OPTIONS,
      useFactory: () => ssoClientOptionsFromEnv(process.env, overrides),
    });
  }

  static forRootAsync(options: SsoClientAsyncOptions): DynamicModule {
    const provider: Provider = options.useFactory
      ? {
          provide: SSO_CLIENT_OPTIONS,
          useFactory: options.useFactory,
          inject: options.inject as never[],
        }
      : {
          provide: SSO_CLIENT_OPTIONS,
          useFactory: (factory: {
            createSsoClientOptions: () => SsoClientOptions;
          }) => factory.createSsoClientOptions(),
          inject: [(options.useClass ?? options.useExisting) as never],
        };

    return this.build(provider, options.imports ?? []);
  }

  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(cookieParser())
      .forRoutes({ path: '{*splat}', method: RequestMethod.ALL });
  }

  private static build(
    optionsProvider: Provider,
    imports: DynamicModule['imports'] = [],
  ): DynamicModule {
    return {
      module: SsoClientModule,
      global: true,
      imports,
      controllers: [SsoAuthController],
      providers: [
        optionsProvider,
        ...services,
        { provide: APP_GUARD, useClass: SsoRbacGuard },
        { provide: APP_FILTER, useClass: SsoLoginRequiredFilter },
      ],
      exports: [optionsProvider, ...services],
    };
  }
}
