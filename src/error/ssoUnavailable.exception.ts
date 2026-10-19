import { HttpException, HttpStatus } from '@nestjs/common';

export class SsoUnavailableException extends HttpException {
  constructor(readonly reason: string) {
    super(
      {
        statusCode: HttpStatus.SERVICE_UNAVAILABLE,
        error: 'sso_unavailable',
        message:
          'o SSO nao respondeu e a credencial nao pode ser conferida agora; tente de novo',
      },
      HttpStatus.SERVICE_UNAVAILABLE,
    );
  }
}
