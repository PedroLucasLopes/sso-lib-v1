import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * Nao ha sessao utilizavel: nunca houve, expirou, ou o SSO recusou a renovacao.
 *
 * E diferente de "credencial invalida". Aqui o caminho de volta existe e e
 * conhecido: mandar a pessoa ao login e traze-la de volta ao lugar onde ela
 * estava. Quem decide COMO fazer isso e o `SsoLoginRequiredFilter`, porque a
 * resposta certa depende de quem perguntou:
 *
 *   - navegacao de pagina  -> 302 para o login, com `returnTo`
 *   - chamada de API       -> 401 com o endereco do login no corpo
 *
 * Lancar em vez de responder aqui e deliberado. Um guard que chama
 * `res.redirect()` e devolve `false` faz o Nest tentar responder de novo, e o
 * resultado e "Cannot set headers after they are sent". Ja aconteceu neste
 * projeto.
 */
export class SsoLoginRequiredException extends HttpException {
  constructor(
    /** Endereco absoluto de `/auth/login`, com o `returnTo` ja embutido. */
    readonly loginUrl: string,
    /** Para onde a pessoa volta depois de entrar. */
    readonly returnTo: string,
    /** O que de fato faltou, para log e diagnostico. */
    readonly reason: string,
  ) {
    super(
      {
        // Nome estavel, para o front reagir sem depender de texto.
        error: 'login_required',
        error_description: reason,
        login_url: loginUrl,
        return_to: returnTo,
      },
      HttpStatus.UNAUTHORIZED,
    );
  }
}
