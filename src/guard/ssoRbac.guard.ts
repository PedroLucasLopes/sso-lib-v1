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
  SSO_FRESH_GRANT,
  SSO_LEVEL_AUTHENTICATED,
  SSO_LEVEL_LOGIN,
  SSO_LEVEL_PUBLIC,
  SSO_SAFE_METHODS,
} from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type {
  AccessTokenClaims,
  SsoPermission,
  SsoUser,
} from '../dto/ssoSession.dto';
import { SsoLoginRequiredException } from '../error/loginRequired.exception';
import { isPageNavigation } from '../error/pageNavigation';
import {
  SsoIntrospectionService,
  type SsoGrantState,
} from '../service/introspection.service';
import { SsoJwksVerifierService } from '../service/jwksVerifier.service';
import { SsoPermissionsService } from '../service/permissions.service';
import { SsoOAuthService } from '../service/ssoOAuth.service';
import { SsoSessionService } from '../service/ssoSession.service';

@Injectable()
export class SsoRbacGuard implements CanActivate {
  private readonly logger = new Logger(SsoRbacGuard.name);
  private readonly routePrefix: string;
  private readonly matchers = new Map<string, RegExp>();

  private readonly ownOrigin: string;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private reflector: Reflector,
    private sessions: SsoSessionService,
    private oauth: SsoOAuthService,
    private verifier: SsoJwksVerifierService,
    private permissions: SsoPermissionsService,
    private introspection: SsoIntrospectionService,
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

    const bearer = this.readBearer(req);

    if (!bearer) this.assertCsrf(req);

    let accessToken = bearer ?? (await this.fromSession(req, res));

    let claims;

    try {
      claims = await this.verifier.verify(accessToken);
    } catch (firstError) {
      this.logger.warn(
        `access token recusado: ${firstError instanceof Error ? firstError.message : String(firstError)}`,
      );

      if (bearer) {
        throw new UnauthorizedException({
          statusCode: 401,
          error: 'invalid_token',
          message: 'access token invalido ou expirado',
        });
      }

      const stored = this.sessions.read(req);
      const renewed = stored ? await this.oauth.forceRefresh(stored, res) : null;

      if (!renewed) {
        this.loginRequired(req, 'token da sessao nao verifica e a renovacao falhou');
      }

      this.sessions.remember(req, renewed);

      try {
        claims = await this.verifier.verify(renewed.accessToken);
        accessToken = renewed.accessToken;
      } catch {
        this.sessions.clear(res);
        this.loginRequired(req, 'nem o token renovado verifica');
      }
    }

    const grant = claims.jti
      ? await this.introspection.check(accessToken, claims.jti, {
          fresh: this.hasLevel(context, SSO_FRESH_GRANT),
        })
      : null;

    if (grant && !grant.active) {
      this.logger.warn(`o SSO encerrou o acesso de ${claims.sub}`);

      if (bearer) {
        throw new UnauthorizedException({
          statusCode: 401,
          error: 'invalid_token',
          message: 'access token revogado no SSO',
        });
      }

      this.sessions.clear(res);
      this.loginRequired(req, 'o SSO encerrou o acesso desta sessao');
    }

    let roles = claims.roles ?? [];
    let perm = claims.perm;

    if (grant?.active && grant.roles && this.changed(grant, roles, perm)) {
      this.logger.log(
        `papel de ${claims.sub} mudou no SSO: [${roles.join(', ')}] -> [${grant.roles.join(', ')}]`,
      );

      roles = grant.roles;
      perm = grant.perm ?? perm;

      if (!bearer) {
        const renewed = await this.renewForChange(req, res);

        if (renewed) {
          accessToken = renewed.accessToken;
          roles = renewed.claims.roles ?? roles;
          perm = renewed.claims.perm ?? perm;

          this.introspection.remember(renewed.claims.jti, {
            active: true,
            roles,
            perm,
          });
        }
      }
    }

    if (!bearer) {
      req.headers.authorization = `Bearer ${accessToken}`;
    }

    const permissions = roles.length
      ? await this.permissions.forRoles(roles, perm)
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

    user.permissions = roles.length
      ? await this.permissions.forRoles(roles, perm, { revalidate: true })
      : [];

    if (this.isAllowed(user.permissions, path, method)) return true;

    this.logger.warn(`negado: ${roles.join(', ') || 'sem papel'} em ${method} ${path}`);

    throw new NotFoundException(`Cannot ${req.method} ${req.originalUrl}`);
  }

  private assertCsrf(req: Request): void {
    if (SSO_SAFE_METHODS.includes(req.method.toUpperCase())) return;

    const origin = req.headers.origin;

    if (typeof origin === 'string' && origin !== this.ownOrigin) {
      this.logger.warn(
        `CSRF: Origin ${origin} em ${req.method} ${req.path}, esperado ${this.ownOrigin}`,
      );

      throw new ForbiddenException({
        statusCode: 403,
        error: 'origin_not_allowed',
        message: 'origem nao permitida',
      });
    }

    const session = this.sessions.read(req);

    if (!session) return;

    const sent = req.headers[SSO_CSRF_HEADER];

    const checks =
      typeof sent === 'string' &&
      this.sameToken(sent, session.csrfToken);

    if (!checks) {
      this.logger.warn(
        `CSRF: header ${SSO_CSRF_HEADER} ausente ou incorreto em ${req.method} ${req.path}`,
      );

      throw new ForbiddenException({
        statusCode: 403,
        error: 'csrf_token_invalid',
        message:
          'requisicao autenticada por cookie precisa do header ' +
          SSO_CSRF_HEADER +
          '; leia o valor no cookie app_csrf ou em GET /auth/me, ou entao ' +
          'use Authorization: Bearer',
      });
    }
  }

  private sameToken(a: string, b: string): boolean {
    const left = Buffer.from(a);
    const right = Buffer.from(b);

    return left.length === right.length && crypto.timingSafeEqual(left, right);
  }

  private returnToFor(req: Request): string {
    if (isPageNavigation(req)) return req.originalUrl;

    const referer = req.headers.referer;

    return typeof referer === 'string' ? referer : '';
  }

  private loginRequired(req: Request, reason: string): never {
    const returnTo = this.returnToFor(req);

    throw new SsoLoginRequiredException(
      this.oauth.loginUrl(returnTo),
      this.oauth.safeReturnTo(returnTo),
      reason,
    );
  }

  private readBearer(req: Request): string | null {
    const header = req.headers.authorization;

    if (!header) return null;

    const [scheme, value] = header.split(' ');

    return scheme?.toLowerCase() === 'bearer' && value ? value : null;
  }

  private async fromSession(req: Request, res: Response): Promise<string> {
    const stored = this.sessions.read(req);

    if (!stored) {
      const jar = (req.cookies ?? {}) as Record<string, string>;
      const names = Object.keys(jar);
      const expected = this.sessions.cookieName;

      this.logger.warn(
        names.length === 0
          ? `credencial ausente em ${req.method} ${req.path}: nenhum cookie chegou`
          : `credencial ausente em ${req.method} ${req.path}: cookies recebidos [` +
              names.map((n) => `${n}=${jar[n]?.length ?? 0}b`).join(', ') +
              `]; esperado "${expected}"` +
              (jar[expected]
                ? ' (presente, mas nao decifrou: COOKIE_SECRET mudou?)'
                : ' (ausente)'),
      );

      this.loginRequired(req, 'sem sessao e sem Authorization: Bearer');
    }

    const session = await this.oauth.refreshIfNeeded(stored, res);

    if (!session) {
      this.loginRequired(req, 'sessao expirada e renovacao recusada pelo SSO');
    }

    this.sessions.remember(req, session);

    return session.accessToken;
  }

  private changed(grant: SsoGrantState, roles: string[], perm: string): boolean {
    const now = [...(grant.roles ?? [])].sort().join('\n');
    const noToken = [...roles].sort().join('\n');

    return now !== noToken || (grant.perm !== undefined && grant.perm !== perm);
  }

  private async renewForChange(
    req: Request,
    res: Response,
  ): Promise<{ accessToken: string; claims: AccessTokenClaims } | null> {
    const stored = this.sessions.read(req);

    if (!stored) return null;

    const renewed = await this.oauth.forceRefresh(stored, res, {
      clearOnFailure: false,
    });

    if (!renewed) return null;

    this.sessions.remember(req, renewed);

    try {
      return {
        accessToken: renewed.accessToken,
        claims: await this.verifier.verify(renewed.accessToken),
      };
    } catch {
      return null;
    }
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

  private normalize(path: string): string {
    let normalized = path;

    const prefix = this.routePrefix;

    if (
      prefix &&
      normalized.startsWith(prefix) &&
      (normalized.length === prefix.length || normalized[prefix.length] === '/')
    ) {
      normalized = normalized.slice(prefix.length);
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
