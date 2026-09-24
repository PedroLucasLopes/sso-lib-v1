import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { SsoLoginRequiredException } from './loginRequired.exception';
import { isPageNavigation } from './pageNavigation';

@Catch(SsoLoginRequiredException)
export class SsoLoginRequiredFilter
  implements ExceptionFilter<SsoLoginRequiredException>
{
  private readonly logger = new Logger(SsoLoginRequiredFilter.name);

  catch(exception: SsoLoginRequiredException, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();

    if (isPageNavigation(req)) {
      this.logger.log(
        `sessao ausente em ${req.method} ${req.originalUrl}: mandando ao login, volta para ${exception.returnTo}`,
      );

      res.redirect(HttpStatus.FOUND, exception.loginUrl);
      return;
    }

    res
      .status(HttpStatus.UNAUTHORIZED)
      .set('Cache-Control', 'no-store')
      .set('WWW-Authenticate', 'Bearer realm="app"')
      .set('Location', exception.loginUrl)
      .json(exception.getResponse());
  }
}
