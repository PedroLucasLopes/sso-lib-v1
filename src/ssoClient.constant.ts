/** Token de injecao das opcoes do modulo. */
export const SSO_CLIENT_OPTIONS = Symbol('SSO_CLIENT_OPTIONS');

/*
 * Nomes BASE dos cookies. O nome real leva um prefixo por aplicacao, montado
 * em `SsoCookieService.name()`.
 *
 * O prefixo nao e enfeite. Cookie e escopado por HOST, e a RFC 6265 secao 8.5
 * e explicita: nao ha isolamento por porta. Duas aplicacoes em
 * `localhost:3000` e `localhost:4000` dividem o mesmo pote de cookies. Com
 * nome fixo, a segunda a fazer login sobrescreveria a sessao da primeira, e o
 * cookie anti-CSRF de uma seria legivel pelo JavaScript da outra.
 */
/** Transacao de login em curso: guarda o code_verifier e o state. */
export const SSO_TX_COOKIE = 'tx';

/** Sessao do usuario na aplicacao. Carrega os tokens, cifrados. */
export const SSO_SESSION_COOKIE = 'session';

/** Vida do cookie de transacao: so a ida e volta ao SSO. */
export const TX_COOKIE_TTL_SECONDS = 300;

/** Rota totalmente aberta: sem sessao, sem RBAC. */
export const SSO_LEVEL_PUBLIC = 'sso:public';

/** Rota do proprio fluxo de login: ainda nao ha sessao. */
export const SSO_LEVEL_LOGIN = 'sso:login';

/** Rota que exige sessao valida, mas dispensa a checagem de permissao. */
export const SSO_LEVEL_AUTHENTICATED = 'sso:authenticated';

/**
 * Cookie LEGIVEL com o token anti-CSRF. Nao e HttpOnly de proposito: o
 * front precisa le-lo para devolve-lo no header. A copia autoritativa vive
 * dentro do cookie de sessao, que e cifrado, entao quem so consegue GRAVAR
 * cookie no dominio nao consegue forjar um par que bata.
 */
export const SSO_CSRF_COOKIE = 'csrf';

/** Header onde o front devolve o token anti-CSRF. */
export const SSO_CSRF_HEADER = 'x-csrf-token';

/**
 * Metodos sem efeito colateral (RFC 9110 secao 9.2.1). Nao precisam de
 * defesa anti-CSRF: o atacante dispara a requisicao, mas nao le a resposta,
 * porque a mesma politica de origem impede.
 */
export const SSO_SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];
