import { HttpException, HttpStatus } from '@nestjs/common';

export type SsoLoginErrorCode =
  | 'access_denied'
  | 'login_expired'
  | 'state_mismatch'
  | 'sso_unavailable'
  | 'login_failed';

const DESCRIPTIONS: Record<SsoLoginErrorCode, string> = {
  access_denied: 'o SSO negou o acesso a esta aplicacao',
  login_expired: 'transacao de login ausente ou expirada; comece o login de novo',
  state_mismatch:
    'a resposta do SSO nao pertence ao login iniciado neste navegador',
  sso_unavailable: 'o SSO nao respondeu como esperado; tente de novo',
  login_failed: 'o login nao pode ser concluido',
};

export class SsoLoginFailedException extends HttpException {
  constructor(
    readonly code: SsoLoginErrorCode,
    readonly reason: string,
  ) {
    super(
      { error: code, error_description: DESCRIPTIONS[code] },
      code === 'sso_unavailable'
        ? HttpStatus.BAD_GATEWAY
        : HttpStatus.UNAUTHORIZED,
    );
  }
}
