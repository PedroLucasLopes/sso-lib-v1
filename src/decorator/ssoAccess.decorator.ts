import { SetMetadata, createParamDecorator } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import {
  SSO_FRESH_GRANT,
  SSO_LEVEL_AUTHENTICATED,
  SSO_LEVEL_LOGIN,
  SSO_LEVEL_PUBLIC,
} from '../ssoClient.constant';
import type { SsoUser } from '../dto/ssoSession.dto';

/** Rota aberta: sem sessao e sem RBAC. Ex.: health check. */
export const SsoPublic = () => SetMetadata(SSO_LEVEL_PUBLIC, true);

/** Rota do proprio fluxo de login, onde ainda nao ha sessao. */
export const SsoLogin = () => SetMetadata(SSO_LEVEL_LOGIN, true);

/**
 * Exige sessao valida mas dispensa a checagem de permissao por rota.
 * Util para endpoints que todo usuario autenticado pode chamar, como
 * "quem sou eu" ou logout.
 */
export const SsoAuthenticated = () => SetMetadata(SSO_LEVEL_AUTHENTICATED, true);

/**
 * Pergunta ao SSO pelo estado do grant a cada chamada, sem esperar a janela de
 * `grantCheckSeconds`. Serve a "quem sou eu" e a rota sensivel o bastante para
 * nao aceitar 30 segundos de atraso numa revogacao. Custa uma chamada ao SSO
 * por requisicao: use com parcimonia.
 */
export const SsoFreshGrant = () => SetMetadata(SSO_FRESH_GRANT, true);

/** Injeta a identidade resolvida pelo guard no handler. */
export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): SsoUser | undefined => {
    const request = context.switchToHttp().getRequest<Request>();

    return (request as Request & { ssoUser?: SsoUser }).ssoUser;
  },
);

/**
 * Injeta o access token ja verificado pelo guard.
 *
 * Serve para repassar a identidade adiante, quando esta aplicacao precisa
 * chamar outro servico do ecossistema em nome do mesmo usuario. Vem do header
 * quando o cliente o enviou, ou da sessao quando o guard o hidratou, e o
 * handler nao precisa distinguir os dois casos.
 */
export const CurrentToken = createParamDecorator(
  (_data: unknown, context: ExecutionContext): string | undefined => {
    const request = context.switchToHttp().getRequest<Request>();

    return (request as Request & { ssoAccessToken?: string }).ssoAccessToken;
  },
);
