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

/**
 * Conecta uma aplicacao NestJS ao ecossistema do SSO.
 *
 * O padrao e o token-mediating backend da RFC 10017 secao 6.2: a aplicacao
 * age como cliente confidencial, conduz o Authorization Code + PKCE, guarda o
 * refresh token do lado do servidor e ENTREGA o access token a quem tem a
 * sessao, por `GET /auth/token`. Dai em diante vale `Authorization: Bearer`.
 *
 * Nao e um BFF (secao 6.1): ali o token nunca sairia do servidor. Aqui ele
 * sai, de proposito, porque quem consome a API e a propria aplicacao e, mais
 * adiante, o front dela.
 *
 * Registra o fluxo OAuth completo, a verificacao do token contra o JWKS, o
 * RBAC por rota e o `cookie-parser`. A aplicacao ganha `/auth/login`,
 * `/auth/callback`, `/auth/token`, `/auth/logout` e `/auth/me` sem escrever
 * nada, e todas as demais rotas passam a exigir credencial e permissao por
 * padrao. Marque as excecoes com `@SsoPublic()` ou `@SsoAuthenticated()`.
 *
 * O caminho curto, para uma API nova, le as variaveis de ambiente do
 * ecossistema (ver `ssoClientOptionsFromEnv`):
 *
 * ```ts
 * @Module({
 *   imports: [
 *     ConfigModule.forRoot({ isGlobal: true }),
 *     SsoClientModule.forRootFromEnv(),
 *   ],
 * })
 * ```
 *
 * Quem precisa montar a configuracao de outro jeito usa `forRoot` ou
 * `forRootAsync`.
 */
@Module({})
export class SsoClientModule implements NestModule {
  static forRoot(options: SsoClientOptions): DynamicModule {
    return this.build({
      provide: SSO_CLIENT_OPTIONS,
      useValue: options,
    });
  }

  /**
   * Opcoes lidas das variaveis de ambiente, com `overrides` ganhando delas.
   *
   * Fabrica, e nao valor: o ambiente e lido quando o provider nasce, depois
   * de o `ConfigModule.forRoot()` da aplicacao ter carregado o `.env`.
   * Configuracao incompleta derruba o boot com a lista do que falta.
   */
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

  /**
   * `cookie-parser` em toda rota da aplicacao.
   *
   * Sem ele `req.cookies` chega vazio, a sessao nunca e lida e a pessoa entra
   * num laco de login sem erro nenhum na tela ou no log. Era um passo manual
   * no bootstrap, e o mais facil de esquecer numa API nova. Quem ja registra
   * no `main.ts` nao e afetado: o middleware pula a requisicao cujos cookies
   * ja foram lidos.
   */
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
        // Guard global: seguro por padrao. Rota nova nasce protegida, e
        // esquecer o decorator fecha o acesso em vez de abrir.
        { provide: APP_GUARD, useClass: SsoRbacGuard },
        // Traduz "nao ha sessao" em 302 para navegacao de pagina e em 401
        // com `login_required` para chamada de API. Sem ele, a pessoa que
        // volta a uma aba velha ve JSON de erro em vez de ser relogada.
        { provide: APP_FILTER, useClass: SsoLoginRequiredFilter },
      ],
      exports: [optionsProvider, ...services],
    };
  }
}
