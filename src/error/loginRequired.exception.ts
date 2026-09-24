import { HttpException, HttpStatus } from '@nestjs/common';

export class SsoLoginRequiredException extends HttpException {
  constructor(
    readonly loginUrl: string,
    readonly returnTo: string,
    readonly reason: string,
  ) {
    super(
      {
        error: 'login_required',
        error_description: reason,
        login_url: loginUrl,
        return_to: returnTo,
      },
      HttpStatus.UNAUTHORIZED,
    );
  }
}
