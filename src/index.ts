export { SsoClientModule } from './ssoClient.module';

export {
  SsoPublic,
  SsoLogin,
  SsoAuthenticated,
  SsoFreshGrant,
  CurrentUser,
  CurrentToken,
} from './decorator/ssoAccess.decorator';

export { SsoRbacGuard } from './guard/ssoRbac.guard';
export { SsoLoginRequiredException } from './error/loginRequired.exception';
export { SsoLoginRequiredFilter } from './error/loginRequired.filter';
export { SsoLoginFailedException } from './error/loginFailed.exception';
export type { SsoLoginErrorCode } from './error/loginFailed.exception';

export { SsoOAuthService } from './service/ssoOAuth.service';
export { SsoSessionService } from './service/ssoSession.service';
export { SsoJwksVerifierService } from './service/jwksVerifier.service';
export { SsoPermissionsService } from './service/permissions.service';
export { SsoIntrospectionService } from './service/introspection.service';
export type { SsoGrantState } from './service/introspection.service';
export { SsoDiscoveryService } from './service/discovery.service';
export { SsoClientAssertionService } from './service/clientAssertion.service';
export { SsoCookieService } from './cookie/cookie.service';

export {
  SSO_CLIENT_OPTIONS,
  SSO_CSRF_COOKIE,
  SSO_CSRF_HEADER,
} from './ssoClient.constant';

export { loadPrivateKeyPem } from './config/privateKeySource';
export { ssoClientOptionsFromEnv } from './config/ssoClientEnv';
export type { PrivateKeySource } from './config/privateKeySource';

export type {
  SsoClientOptions,
  SsoClientAsyncOptions,
  SsoClientOptionsFactory,
} from './config/ssoClientOptions';

export type {
  SsoUser,
  SsoMe,
  SsoPermission,
  SsoSessionData,
  AccessTokenClaims,
} from './dto/ssoSession.dto';
