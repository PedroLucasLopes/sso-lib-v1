import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import * as crypto from 'node:crypto';
import {
  SSO_CLIENT_OPTIONS,
  SSO_CSRF_HEADER,
  SSO_LEVEL_AUTHENTICATED,
  SSO_LEVEL_LOGIN,
  SSO_LEVEL_PUBLIC,
  SSO_SAFE_METHODS,
} from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type { SsoPermission, SsoUser } from '../dto/ssoSession.dto';
import { SsoLoginRequiredException } from '../error/loginRequired.exception';
import { isPageNavigation } from '../error/pageNavigation';
import { SsoJwksVerifierService } from '../service/jwksVerifier.service';
import { SsoPermissionsService } from '../service/permissions.service';
import { SsoOAuthService } from '../service/ssoOAuth.service';
import { SsoSessionService } from '../service/ssoSession.service';

/**
 * Guard unico: sessao, renovacao silenciosa e RBAC por rota.
 *
 * Sobre o casamento de caminho: o caminho da REQUISICAO nunca vira padrao.
 * A versao anterior fazia exatamente isso, montando `new RegExp(req.path)` e
 * testando a permissao contra ela. Alem de inverter a relacao, transformava
 * metacaracteres de regex no caminho em bypass de autorizacao: um pedido a
 * `/api/.*` casava com qualquer permissao. Aqui quem vira padrao e a
 * permissao, que e cadastrada por administrador, e o caminho da requisicao e
 * sempre apenas o texto testado.
 */
@Injectable()
export class SsoRbacGuard implements CanActivate {
  private readonly logger = new Logger(SsoRbacGuard.name);
  private readonly routePrefix: string;
  private readonly matchers = new Map<string, RegExp>();

  /** Origem desta aplicacao, para recusar `Origin` de outro site. */
  private readonly ownOrigin: string;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private reflector: Reflector,
    private sessions: SsoSessionService,
    private oauth: SsoOAuthService,
    private verifier: SsoJwksVerifierService,
    private permissions: SsoPermissionsService,
  ) {
    this.routePrefix = (
      options.routePrefix ?? new URL(options.appBaseUrl).pathname
    ).replace(/\/+$/, '');

    this.ownOrigin = new URL(options.appBaseUrl).origin;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.hasLevel(context, SSO_LEVEL_PUBLIC)) return true;
    if (this.hasLevel(context, SSO_LEVEL_LOGIN)) return true;

    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();

    // Duas formas de apresentar credencial, nesta precedencia:
    //
    //   1. Authorization: Bearer  - explicito. E como uma aplicacao cliente
    //      chama a API depois de pegar o token em GET /auth/token.
    //   2. cookie de sessao       - implicito. Usado pela navegacao direta,
    //      e e a unica forma que permite renovacao automatica, porque o
    //      refresh token so existe do lado do servidor.
    //
    // Bearer primeiro porque e explicito, e porque nao carrega o risco de
    // CSRF que o cookie carrega.
    const bearer = this.readBearer(req);

    // Antes de qualquer coisa que mude estado, inclusive antes da renovacao
    // silenciosa do token: requisicao forjada nao pode consumir uma rotacao
    // de refresh token.
    if (!bearer) this.assertCsrf(req);

    let accessToken = bearer ?? (await this.fromSession(req, res));

    let claims;

    try {
      claims = await this.verifier.verify(accessToken);
    } catch (primeiroErro) {
      this.logger.warn(
        `access token recusado: ${primeiroErro instanceof Error ? primeiroErro.message : String(primeiroErro)}`,
      );

      // Bearer ruim e problema de quem enviou: 401 seco, sem mexer na sessao.
      if (bearer) {
        throw new UnauthorizedException('access token invalido ou expirado');
      }

      /* Veio da sessao. Antes de desistir, gasta o refresh token: o access
       * token pode ter sido invalidado por rotacao de chave no SSO ou por
       * relogio fora de hora, e nos dois casos a sessao ainda esta boa. Sem
       * esta tentativa, uma rotacao de chave deslogaria todo mundo de uma vez. */
      const stored = this.sessions.read(req);
      const renovada = stored ? await this.oauth.forceRefresh(stored, res) : null;

      if (!renovada) {
        this.loginRequired(req, 'token da sessao nao verifica e a renovacao falhou');
      }

      try {
        claims = await this.verifier.verify(renovada.accessToken);
        accessToken = renovada.accessToken;
      } catch {
        this.sessions.clear(res);
        this.loginRequired(req, 'nem o token renovado verifica');
      }
    }

    // Reconheceu o login pelo cookie: preenche o header como se o cliente o
    // tivesse enviado. A partir daqui existe UM caminho so. Controller,
    // interceptor e qualquer chamada de saida leem `Authorization` sem
    // precisar saber como o usuario se identificou.
    //
    // Escrito depois da verificacao, de proposito: token que nao passou nao
    // entra no request.
    if (!bearer) {
      req.headers.authorization = `Bearer ${accessToken}`;
    }

    // O token traz o papel; as rotas que ele libera vem do SSO, cacheadas
    // pelo hash. Uma busca por papel, nao uma por requisicao.
    const roles = claims.roles ?? [];
    const permissions = roles.length
      ? await this.permissions.forRoles(roles, claims.perm)
      : [];

    const user: SsoUser = {
      id: claims.sub,
      email: claims.email,
      name: claims.name,
      roles,
      permissions,
    };

    const request = req as Request & {
      ssoUser?: SsoUser;
      ssoAccessToken?: string;
    };

    request.ssoUser = user;
    request.ssoAccessToken = accessToken;

    if (this.hasLevel(context, SSO_LEVEL_AUTHENTICATED)) return true;

    const path = this.normalize(req.path);
    const method = req.method.toUpperCase();

    if (this.isAllowed(user.permissions, path, method)) return true;

    /* Rota nova ou permissao recem-concedida: pergunta de novo ao SSO antes de
     * negar, entao o que se libera no console vale na requisicao seguinte. */
    user.permissions = roles.length
      ? await this.permissions.forRoles(roles, claims.perm, { revalidate: true })
      : [];

    if (this.isAllowed(user.permissions, path, method)) return true;

    this.logger.warn(`negado: ${roles.join(', ') || 'sem papel'} em ${method} ${path}`);

    /* Sem permissao, ou rota que nao existe no catalogo do SSO: o mesmo 404 de
     * um caminho que nao existe na aplicacao. Quem nao pode usar a rota nao
     * descobre que ela existe (RFC 9110 secao 15.5.4). */
    throw new NotFoundException(`Cannot ${req.method} ${req.originalUrl}`);
  }

  /**
   * Defesa anti-CSRF para as requisicoes autenticadas por COOKIE.
   *
   * A RFC 10017 secao 6.2.3.2 exige que o token-mediating backend se defenda
   * de CSRF, e a razao e mecanica: o navegador anexa o cookie de sessao mesmo
   * quando quem disparou a requisicao foi outro site. O `Authorization:
   * Bearer` nao tem esse problema, porque o navegador nunca o anexa sozinho.
   * Por isso esta checagem so vale quando a credencial veio do cookie.
   *
   * Sao duas barreiras:
   *
   *   1. Token de dupla submissao. O valor autoritativo vive DENTRO do cookie
   *      de sessao, que e cifrado, e o front devolve a copia legivel no
   *      header. Quem consegue apenas GRAVAR cookie no dominio, por subdominio
   *      tomado ou resposta injetada, nao produz um par que bata, porque nao
   *      sabe cifrar o lado de dentro.
   *   2. `Origin`. Recusado quando PRESENTE e de outro site. Nao e exigido,
   *      para nao quebrar cliente que nao o envia; e barreira extra, nao a
   *      principal.
   */
  private assertCsrf(req: Request): void {
    if (SSO_SAFE_METHODS.includes(req.method.toUpperCase())) return;

    const origin = req.headers.origin;

    if (typeof origin === 'string' && origin !== this.ownOrigin) {
      this.logger.warn(
        `CSRF: Origin ${origin} em ${req.method} ${req.path}, esperado ${this.ownOrigin}`,
      );

      throw new ForbiddenException('origem nao permitida');
    }

    const session = this.sessions.read(req);

    // Sem sessao nao ha o que proteger, e o 401 de `fromSession` diagnostica
    // melhor do que um 403 generico daqui.
    if (!session) return;

    const enviado = req.headers[SSO_CSRF_HEADER];

    const confere =
      typeof enviado === 'string' &&
      this.sameToken(enviado, session.csrfToken);

    if (!confere) {
      this.logger.warn(
        `CSRF: header ${SSO_CSRF_HEADER} ausente ou incorreto em ${req.method} ${req.path}`,
      );

      throw new ForbiddenException(
        'requisicao autenticada por cookie precisa do header ' +
          SSO_CSRF_HEADER +
          '; leia o valor no cookie app_csrf ou em GET /auth/me, ou entao ' +
          'use Authorization: Bearer',
      );
    }
  }

  /** Comparacao em tempo constante: `!==` vaza o tamanho do prefixo certo. */
  private sameToken(a: string, b: string): boolean {
    const left = Buffer.from(a);
    const right = Buffer.from(b);

    return left.length === right.length && crypto.timingSafeEqual(left, right);
  }

  /**
   * Onde a pessoa estava quando a sessao morreu.
   *
   * Duas origens, porque sao dois casos:
   *
   *   - **Navegacao de pagina.** `originalUrl` E o lugar: ela pediu aquela URL.
   *   - **Chamada de API.** `originalUrl` seria `/api/accessory`, uma rota de
   *     backend, e nao a tela que a pessoa via. O `Referer` de um `fetch`
   *     same-origin carrega a pagina que disparou a chamada, que e exatamente
   *     `/accessories`. E o unico lugar onde o backend fica sabendo disso.
   *
   * `Referer` e entrada do navegador, nao segredo, entao passa por
   * `safeReturnTo` como qualquer outro destino.
   */
  private returnToFor(req: Request): string {
    if (isPageNavigation(req)) return req.originalUrl;

    const referer = req.headers.referer;

    return typeof referer === 'string' ? referer : '';
  }

  /** Sem sessao utilizavel: manda ao login e volta para onde a pessoa estava. */
  private loginRequired(req: Request, motivo: string): never {
    const returnTo = this.returnToFor(req);

    throw new SsoLoginRequiredException(
      this.oauth.loginUrl(returnTo),
      this.oauth.safeReturnTo(returnTo),
      motivo,
    );
  }

  /** RFC 6750 secao 2.1: `Authorization: Bearer <token>`. */
  private readBearer(req: Request): string | null {
    const header = req.headers.authorization;

    if (!header) return null;

    const [scheme, value] = header.split(' ');

    return scheme?.toLowerCase() === 'bearer' && value ? value : null;
  }

  /**
   * Caminho do cookie. Renova antes de devolver: se o access token acabou de
   * expirar, quem navega nem percebe. Isso so e possivel aqui porque o
   * refresh token vive na sessao, do lado do servidor.
   */
  private async fromSession(req: Request, res: Response): Promise<string> {
    const stored = this.sessions.read(req);

    if (!stored) {
      // Diagnostico: "credencial ausente" tem tres causas muito diferentes e
      // indistinguiveis de fora. Registrar o que CHEGOU separa as tres:
      //   . nenhum cookie          -> navegador nao enviou, ou descartou
      //   . cookie com tamanho ok  -> falha ao decifrar (COOKIE_SECRET mudou)
      //   . cookie curto demais    -> truncado no caminho
      const jar = (req.cookies ?? {}) as Record<string, string>;
      const nomes = Object.keys(jar);
      const esperado = this.sessions.cookieName;

      this.logger.warn(
        nomes.length === 0
          ? `credencial ausente em ${req.method} ${req.path}: nenhum cookie chegou`
          : `credencial ausente em ${req.method} ${req.path}: cookies recebidos [` +
              nomes.map((n) => `${n}=${jar[n]?.length ?? 0}b`).join(', ') +
              `]; esperado "${esperado}"` +
              (jar[esperado]
                ? ' (presente, mas nao decifrou: COOKIE_SECRET mudou?)'
                : ' (ausente)'),
      );

      this.loginRequired(req, 'sem sessao e sem Authorization: Bearer');
    }

    const session = await this.oauth.refreshIfNeeded(stored, res);

    if (!session) {
      // O refresh token morreu: expirou, foi revogado, ou a deteccao de reuso
      // derrubou a familia. Nao ha como renovar em silencio, so refazendo o
      // login. Mandar de volta ao lugar de origem e o que torna isso invisivel.
      this.loginRequired(req, 'sessao expirada e renovacao recusada pelo SSO');
    }

    return session.accessToken;
  }

  private isAllowed(
    permissions: SsoPermission[],
    path: string,
    method: string,
  ): boolean {
    return permissions.some(
      (permission) =>
        permission.method.toUpperCase() === method &&
        this.compile(permission.path).test(path),
    );
  }

  /**
   * Compila o caminho da PERMISSAO num matcher.
   * `:param` casa um segmento; qualquer outro caractere e literal escapado.
   */
  private compile(permissionPath: string): RegExp {
    const cached = this.matchers.get(permissionPath);

    if (cached) return cached;

    const pattern = this.normalize(permissionPath)
      .split('/')
      .map((segment) => {
        if (segment.startsWith(':')) return '[^/]+';
        if (segment === '*') return '[^/]*';
        return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      })
      .join('/');

    const matcher = new RegExp(`^${pattern}$`);

    this.matchers.set(permissionPath, matcher);

    return matcher;
  }

  /**
   * Tira o prefixo global e a barra final, para que `/api/equipment/` e
   * `/equipment` cheguem na mesma forma que o SSO guarda.
   */
  private normalize(path: string): string {
    let normalized = path;

    /* Recorta na FRONTEIRA. Sem o teste do proximo caractere, `/ssouser`
     * viraria `/user` e um caminho que nao e desta aplicacao casaria com
     * uma permissao dela. Hoje o roteador do Nest nao deixa chegar aqui,
     * mas a normalizacao nao deve depender disso. */
    const prefixo = this.routePrefix;

    if (
      prefixo &&
      normalized.startsWith(prefixo) &&
      (normalized.length === prefixo.length || normalized[prefixo.length] === '/')
    ) {
      normalized = normalized.slice(prefixo.length);
    }

    normalized = normalized.replace(/\/{2,}/g, '/');

    if (normalized.length > 1) {
      normalized = normalized.replace(/\/+$/, '');
    }

    return normalized.startsWith('/') ? normalized : `/${normalized}`;
  }

  private hasLevel(context: ExecutionContext, level: string): boolean {
    return (
      this.reflector.getAllAndOverride<boolean>(level, [
        context.getHandler(),
        context.getClass(),
      ]) === true
    );
  }
}
