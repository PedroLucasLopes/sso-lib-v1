import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * Por que o login nao se completou, num nome estavel.
 *
 * E o que o callback devolve ao front em `?auth_error=`, e o `error` do corpo
 * JSON. A lista e fechada de proposito: o front traduz cada codigo e trata o
 * que vier fora dela como falha generica. Texto lido da URL nunca vira
 * mensagem, pela mesma razao da tela de login do IdP: seria um mural para quem
 * quisesse enganar alguem a partir de um dominio confiavel.
 *
 *   - `access_denied`   o SSO negou: a conta existe, mas nao tem papel no projeto
 *   - `login_expired`   nao ha transacao neste navegador, ou ela passou do prazo
 *   - `state_mismatch`  a resposta nao e do login iniciado neste navegador
 *   - `sso_unavailable` o SSO falhou ou nao respondeu
 *   - `login_failed`    o resto: resposta que nao pode ser aceita, ou troca recusada
 */
export type SsoLoginErrorCode =
  | 'access_denied'
  | 'login_expired'
  | 'state_mismatch'
  | 'sso_unavailable'
  | 'login_failed';

/** Texto fixo por codigo. A resposta nunca repete o que veio da URL. */
const DESCRIPTIONS: Record<SsoLoginErrorCode, string> = {
  access_denied: 'o SSO negou o acesso a esta aplicacao',
  login_expired: 'transacao de login ausente ou expirada; comece o login de novo',
  state_mismatch:
    'a resposta do SSO nao pertence ao login iniciado neste navegador',
  sso_unavailable: 'o SSO nao respondeu como esperado; tente de novo',
  login_failed: 'o login nao pode ser concluido',
};

/**
 * O callback nao conseguiu transformar a resposta do SSO numa sessao.
 *
 * Uma pessoa navegando nao ve isto quando a aplicacao configura
 * `loginErrorRedirect`: o callback a devolve ao front com o codigo. Esta
 * excecao e a resposta de chamada que nao e navegacao de pagina, e de
 * aplicacao que nao configurou a opcao.
 */
export class SsoLoginFailedException extends HttpException {
  constructor(
    /** Nome estavel, para o front reagir sem depender de texto. */
    readonly code: SsoLoginErrorCode,
    /** O que de fato aconteceu, para log e diagnostico. Nao vai na resposta. */
    readonly reason: string,
  ) {
    super(
      { error: code, error_description: DESCRIPTIONS[code] },
      // SSO fora do ar e falha de quem esta atras desta aplicacao, nao da
      // credencial de quem pediu.
      code === 'sso_unavailable'
        ? HttpStatus.BAD_GATEWAY
        : HttpStatus.UNAUTHORIZED,
    );
  }
}
