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

export const SsoPublic = () => SetMetadata(SSO_LEVEL_PUBLIC, true);

export const SsoLogin = () => SetMetadata(SSO_LEVEL_LOGIN, true);

export const SsoAuthenticated = () => SetMetadata(SSO_LEVEL_AUTHENTICATED, true);

export const SsoFreshGrant = () => SetMetadata(SSO_FRESH_GRANT, true);

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): SsoUser | undefined => {
    const request = context.switchToHttp().getRequest<Request>();

    return (request as Request & { ssoUser?: SsoUser }).ssoUser;
  },
);

export const CurrentToken = createParamDecorator(
  (_data: unknown, context: ExecutionContext): string | undefined => {
    const request = context.switchToHttp().getRequest<Request>();

    return (request as Request & { ssoAccessToken?: string }).ssoAccessToken;
  },
);
