import { ModuleMetadata, Type } from '@nestjs/common';

export interface SsoClientOptions {
  /**
   * IDENTIDADE publica do Authorization Server, sem barra no fim.
   * Ex.: https://exemplo.com/sso
   *
   * E a claim `iss` do token e a URL que o NAVEGADOR visita. Nao e
   * necessariamente um endereco alcancavel a partir deste processo.
   */
  issuer: string;

  /**
   * ENDERECO de rede do SSO para chamadas servidor a servidor, quando
   * diferente do issuer. Ex.: `http://sso:8080/sso` dentro do compose.
   *
   * Existe porque as duas coisas divergem em container: `localhost:8080`
   * dentro deste processo e ELE MESMO, nao o SSO. O discovery e o token
   * endpoint passam por aqui; o authorization endpoint continua publico,
   * porque quem o abre e o navegador do usuario.
   *
   * A validacao nao afrouxa: o `issuer` devolvido pelo discovery continua
   * tendo de bater com o publico, como manda a RFC 8414 secao 3.3.
   */
  internalBaseUrl?: string;

  /** `Project.clientId` cadastrado no SSO. */
  clientId: string;

  /**
   * Chave privada da aplicacao em PEM (PKCS8), usada para assinar a
   * asserção `private_key_jwt` (RFC 7523 secao 2.2). A publica correspondente
   * fica cadastrada no SSO. Nunca sai deste processo.
   */
  clientPrivateKeyPem: string;

  /**
   * Base publica DESTA aplicacao, incluindo o prefixo global.
   * Ex.: https://exemplo.com/api
   */
  appBaseUrl: string;

  /**
   * Chave de 32 bytes em hex que cifra os cookies.
   * Gere com: openssl rand -hex 32
   */
  cookieSecret: string;

  /** Para onde mandar o usuario depois do login, sem `returnTo`. Default: `/`. */
  postLoginRedirect?: string;

  /**
   * Tela do front que explica por que o login nao se completou. Sem ela, o
   * callback recusado responde JSON, como sempre respondeu.
   *
   * Com ela, a navegacao de pagina que chega ao callback com falha volta para
   * ca, pelo mesmo documento do login bem-sucedido, com `?auth_error=<codigo>`
   * (ver `SsoLoginErrorCode`). Quando a resposta era da transacao deste
   * navegador, vai tambem `&returnTo=<caminho pedido>`, ja passado por
   * `safeReturnTo`.
   *
   * PRECISA ser tela que nao exige sessao. Se o guard do front mandar ao login
   * antes de ler `auth_error`, o SSO recusa de novo, o callback devolve para ca
   * e o ciclo se repete sozinho, sem clique nenhum. E por isso que a opcao nao
   * tem default.
   *
   * Caminho, como `/sign-in-error`, ou URL http(s) absoluta.
   */
  loginErrorRedirect?: string;

  /**
   * RFC 10017 secao 6.1.3.2: Secure e HttpOnly sao MUST. Deixe `false` apenas
   * em desenvolvimento sobre HTTP.
   */
  cookieSecure?: boolean;

  /**
   * Default `strict`, como pede a RFC 10017 secao 6.1.3.2.
   *
   * `SameSite` compara SITE, nao origem: porta e subdominio nao contam, entao
   * `sso.exemplo.com` e `app.exemplo.com` sao o mesmo site e `strict` funciona.
   * So baixe para `lax` se o SSO viver em outro dominio registravel.
   *
   * O cookie de transacao do login e sempre `lax`, independente disto: o
   * retorno do provedor federado e uma navegacao cross-site de verdade.
   */
  cookieSameSite?: 'lax' | 'strict' | 'none';

  /**
   * Prefixo removido do caminho antes de casar com as permissoes do token.
   * O SSO guarda `/equipment`, o Express ve `/api/equipment`.
   * Default: o pathname de `appBaseUrl`.
   */
  routePrefix?: string;

  /**
   * Prefixo dos nomes de cookie desta aplicacao.
   *
   * Default: oito digitos derivados do `clientId`, que ja e unico por
   * aplicacao. Passe um valor legivel se preferir ver `krloc_session` em vez
   * de `a1b2c3d4_session` nas ferramentas do navegador.
   *
   * Precisa ser DIFERENTE entre aplicacoes que compartilhem host. A RFC 6265
   * secao 8.5 nao isola cookie por porta, entao em desenvolvimento todas as
   * aplicacoes em `localhost` dividem o mesmo pote.
   */
  cookiePrefix?: string;

  /**
   * Por quanto tempo o cookie de sessao vive no navegador, em segundos.
   *
   * Tem de acompanhar o `REFRESH_TOKEN_TTL` e o `AUTH_SESSION_TTL` do SSO. O
   * menor dos tres e quem manda: cookie de 14 dias com refresh token de 90
   * derruba a sessao no dia 14, e ninguem entende por que.
   *
   * Default: 90 dias.
   */
  sessionMaxAgeSeconds?: number;

  /**
   * Renova o access token quando faltar menos que isto para expirar.
   * Default: 60 segundos.
   */
  refreshSkewSeconds?: number;

  /**
   * De quanto em quanto tempo o guard pergunta ao SSO se o token de uma sessao
   * ainda vale e qual e o papel da pessoa agora (introspeccao, RFC 7662).
   *
   * E o prazo maximo para uma mudanca feita no SSO chegar a esta aplicacao:
   * papel trocado, pessoa tirada do projeto, aplicacao suspensa, logout. Sem a
   * checagem, esse prazo era a vida do access token, 15 minutos.
   *
   * Cada sessao ativa custa uma chamada ao SSO por janela; sessao parada nao
   * custa nada. `GET /auth/me` e `GET /auth/token` perguntam sempre, sem
   * esperar a janela. `0` pergunta em toda requisicao.
   *
   * Default: 30 segundos.
   */
  grantCheckSeconds?: number;
}

export interface SsoClientOptionsFactory {
  createSsoClientOptions(): Promise<SsoClientOptions> | SsoClientOptions;
}

export interface SsoClientAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  useFactory?: (
    ...args: never[]
  ) => Promise<SsoClientOptions> | SsoClientOptions;
  inject?: unknown[];
  useClass?: Type<SsoClientOptionsFactory>;
  useExisting?: Type<SsoClientOptionsFactory>;
}
