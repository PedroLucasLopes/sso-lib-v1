/**
 * Ponto de entrada separado: `@pedrolucaslopes/sso-client/testing`.
 *
 * Fora do `index.ts` principal de proposito. O que mora aqui pressupoe
 * credenciais de operador do SSO e nao deve ser importavel por engano a partir
 * do codigo de producao de uma aplicacao.
 */
export {
  createSsoSession,
  ensureProjectUser,
  mintAdminToken,
  purgeTestUsers,
  sealSsoCookie,
} from './ssoTestHarness';

export type { SqlClient, SsoTestOptions } from './ssoTestHarness';
