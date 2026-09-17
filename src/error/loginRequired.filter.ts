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

/**
 * Decide o que fazer quando a sessao acabou.
 *
 * Duas respostas, porque sao dois perguntadores diferentes:
 *
 *   - **Navegacao de pagina.** A pessoa digitou o endereco, clicou num link ou
 *     recarregou. Um 401 aqui e um beco sem saida: ela ve uma tela de erro em
 *     JSON. O certo e um 302 para o login, e o `returnTo` a traz de volta ao
 *     lugar exato depois.
 *
 *   - **Chamada de API.** O front pediu dados por `fetch`. Um 302 seria pior do
 *     que inutil: o `fetch` segue o redirect sozinho e o front receberia o HTML
 *     do SSO no lugar do JSON que esperava, sem entender o que houve. O certo e
 *     401 com `error: "login_required"` e o endereco do login no corpo, para o
 *     front guardar onde estava e navegar ele mesmo.
 *
 * A distincao sai de `Sec-Fetch-Dest`, que todo navegador atual manda e que
 * nenhuma pagina consegue forjar. `Accept` cobre o resto.
 */
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

      // 302 e nao 307: a volta do login e sempre GET, mesmo que o pedido
      // original fosse POST. Repetir um POST depois do login seria surpresa.
      res.redirect(HttpStatus.FOUND, exception.loginUrl);
      return;
    }

    res
      .status(HttpStatus.UNAUTHORIZED)
      .set('Cache-Control', 'no-store')
      // RFC 6750 secao 3: recurso protegido que recusa diz como se autenticar.
      .set('WWW-Authenticate', 'Bearer realm="app"')
      // O mesmo endereco tambem em header, para o front nao precisar ler o
      // corpo. Mesma origem, entao e legivel sem CORS.
      .set('Location', exception.loginUrl)
      .json(exception.getResponse());
  }
}
