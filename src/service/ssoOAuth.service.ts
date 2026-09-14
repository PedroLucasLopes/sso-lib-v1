import {
  BadGatewayException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { SsoCookieService } from '../cookie/cookie.service';
import {
  SSO_CLIENT_OPTIONS,
  SSO_TX_COOKIE,
  TX_COOKIE_TTL_SECONDS,
} from '../ssoClient.constant';
import type { SsoClientOptions } from '../config/ssoClientOptions';
import type {
  SsoSessionData,
  SsoTokenError,
  SsoTokenResponse,
  SsoTransaction,
} from '../dto/ssoSession.dto';
import {
  CLIENT_ASSERTION_TYPE,
  SsoClientAssertionService,
} from './clientAssertion.service';
import { SsoDiscoveryService } from './discovery.service';
import { SsoSessionService } from './ssoSession.service';

/**
 * Lado cliente do Authorization Code + PKCE.
 *
 * O `state` e o `code_verifier` vivem num cookie cifrado, e nao mais no
 * Redis. Isso amarra a transacao AO NAVEGADOR, que e o que a RFC 9700 secao
 * 2.1 exige. Com o estado so no Redis, um atacante podia iniciar o proprio
 * login, pegar um par code/state valido e entregar a URL de callback para a
 * vitima, fixando nela a sessao dele.
 */
@Injectable()
export class SsoOAuthService {
  private readonly logger = new Logger(SsoOAuthService.name);
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly postLoginRedirect: string;
  private readonly ownOrigin: string;
  private readonly appBaseUrl: string;
  private readonly refreshSkewSeconds: number;

  constructor(
    @Inject(SSO_CLIENT_OPTIONS) options: SsoClientOptions,
    private cookies: SsoCookieService,
    private discovery: SsoDiscoveryService,
    private assertions: SsoClientAssertionService,
    private sessions: SsoSessionService,
  ) {
    const appBaseUrl = options.appBaseUrl.replace(/\/+$/, '');

    this.issuer = options.issuer.replace(/\/+$/, '');
    this.clientId = options.clientId;
    this.redirectUri = `${appBaseUrl}/auth/callback`;
    // Raiz da origem, nao `${appBaseUrl}/home`: com o front proxiando a API,
    // a raiz e a home do FRONT, que e onde a pessoa espera cair. Uma rota de
    // API como destino de login so faz sentido sem front.
    this.postLoginRedirect = options.postLoginRedirect ?? '/';
    this.ownOrigin = new URL(appBaseUrl).origin;
    this.appBaseUrl = appBaseUrl;
    this.refreshSkewSeconds = options.refreshSkewSeconds ?? 60;
  }

  async beginLogin(res: Response, returnTo?: string): Promise<void> {
    // RFC 7636 secao 7.1: no minimo 256 bits de entropia no verifier.
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier, 'ascii')
      .digest('base64url');

    const state = crypto.randomBytes(32).toString('base64url');

    const transaction: SsoTransaction = {
      state,
      codeVerifier,
      createdAt: Math.floor(Date.now() / 1000),
      returnTo,
    };

    // Sempre `lax`: o retorno do SSO pode ser cross-site, e `strict` nao
    // acompanharia o salto, deixando o callback sem transacao.
    this.cookies.set(res, SSO_TX_COOKIE, transaction, TX_COOKIE_TTL_SECONDS, {
      sameSite: 'lax',
    });

    const { authorization_endpoint: authorizeEndpoint } =
      await this.discovery.metadata();

    const url = new URL(authorizeEndpoint);

    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);

    res.redirect(url.toString());
  }

  async completeLogin(
    req: Request,
    res: Response,
    query: Record<string, unknown>,
  ): Promise<void> {
    const transaction = this.cookies.get<SsoTransaction>(req, SSO_TX_COOKIE);

    this.cookies.clear(res, SSO_TX_COOKIE, { sameSite: 'lax' });

    if (!transaction) {
      throw new UnauthorizedException('transacao de login ausente ou expirada');
    }

    // O SSO pode devolver um erro em vez de um code (RFC 6749 secao 4.1.2.1).
    if (typeof query.error === 'string') {
      const description =
        typeof query.error_description === 'string'
          ? query.error_description
          : '';

      throw new UnauthorizedException(
        `o SSO recusou a autorizacao: ${query.error} ${description}`.trim(),
      );
    }

    // RFC 9207: confere quem respondeu. E a defesa contra mix-up recomendada
    // pela RFC 9700 secao 2.1 para quem fala com mais de um servidor.
    if (typeof query.iss === 'string' && query.iss !== this.issuer) {
      this.logger.warn(`resposta com iss inesperado: ${query.iss}`);
      throw new UnauthorizedException('resposta veio de outro servidor');
    }

    if (
      typeof query.state !== 'string' ||
      !this.timingSafeEqual(query.state, transaction.state)
    ) {
      throw new UnauthorizedException('state nao confere com a transacao');
    }

    if (typeof query.code !== 'string' || !query.code) {
      throw new UnauthorizedException('code ausente na resposta do SSO');
    }

    const age = Math.floor(Date.now() / 1000) - transaction.createdAt;

    if (age > TX_COOKIE_TTL_SECONDS) {
      throw new UnauthorizedException('transacao de login expirada');
    }

    const tokens = await this.requestTokens({
      grant_type: 'authorization_code',
      code: query.code,
      code_verifier: transaction.codeVerifier,
      redirect_uri: this.redirectUri,
    });

    this.sessions.write(res, tokens);

    this.bounceTo(res, this.safeReturnTo(transaction.returnTo));
  }

  /**
   * Renova o access token quando ele esta perto de expirar.
   *
   * Devolve null quando a renovacao falha, o que inclui o caso em que o SSO
   * detectou reuso de refresh token e derrubou a familia. Nesse caso a sessao
   * tem de ser descartada e o usuario mandado de volta ao login.
   */
  /**
   * Endereco absoluto do login, ja com o destino de volta embutido.
   *
   * Absoluto, e nao relativo, porque este valor tambem viaja no corpo de um
   * 401 para o front decidir o que fazer. Relativo so funcionaria se quem
   * recebesse estivesse na mesma base, e o front pode nao estar.
   */
  loginUrl(returnTo?: string): string {
    const destino = this.safeReturnTo(returnTo);

    return `${this.appBaseUrl}/auth/login?returnTo=${encodeURIComponent(destino)}`;
  }

  /**
   * Para onde mandar o usuario depois do login, sem virar redirect aberto.
   *
   * `returnTo` chega pela query string, entao e entrada do atacante. Sem
   * filtro, `?returnTo=https://phishing.example` transformaria a rota de login
   * numa maquina de encaminhar vitimas partindo de um dominio confiavel.
   *
   * Aceita caminho relativo comecando com uma barra so, ou URL absoluta da
   * propria origem. Qualquer outra coisa cai no destino padrao.
   */
  safeReturnTo(candidate?: string): string {
    if (!candidate) return this.postLoginRedirect;

    // `//host` e `/\host` sao protocolo-relativos: o navegador sai do site.
    if (/^\/[/\\]/.test(candidate)) return this.postLoginRedirect;

    if (candidate.startsWith('/')) return candidate;

    try {
      return new URL(candidate).origin === this.ownOrigin
        ? candidate
        : this.postLoginRedirect;
    } catch {
      return this.postLoginRedirect;
    }
  }

  /**
   * Ultima etapa do login: em vez de um 302, devolve um documento da PROPRIA
   * origem que navega sozinho para o destino.
   *
   * Parece rodeio, e e o que permite `SameSite=Strict` na sessao. O retorno do
   * provedor federado e uma cadeia de redirects que comeca em outro site, e o
   * navegador considera a cadeia inteira cross-site. Um cookie `Strict` nao
   * acompanha esse salto: a pagina de destino chegaria sem sessao, devolveria
   * 401, mandaria o usuario para o login de novo e o ciclo recomecaria.
   *
   * Uma navegacao iniciada por ESTE documento e same-site, e aí o cookie vai.
   *
   * Sem JavaScript de proposito: `meta refresh` basta, e o modulo nao impoe
   * politica de CSP a quem usa a biblioteca. O link existe para o caso raro de
   * o refresh estar desabilitado.
   */
  private bounceTo(res: Response, destino: string): void {
    const escapado = destino.replace(
      /[&<>"']/g,
      (c) =>
        ({
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;',
        })[c] as string,
    );

    res
      .status(200)
      .type('html')
      .set('Cache-Control', 'no-store')
      .send(
        [
          '<!doctype html>',
          '<html lang="pt-br"><head><meta charset="utf-8">',
          `<meta http-equiv="refresh" content="0; url=${escapado}">`,
          '<title>Entrando...</title></head>',
          `<body><p>Entrando... <a href="${escapado}">continuar</a></p></body></html>`,
        ].join(''),
      );
  }

  /**
   * Renova AGORA, sem olhar o relogio.
   *
   * `refreshIfNeeded` decide pela data de expiracao, que e o caso comum. Este
   * existe para o outro caso: o access token da sessao nao verificou. Pode ser
   * rotacao de chave de assinatura no SSO, relogio fora de hora, ou o token
   * ter sido invalidado. Tentar renovar antes de desistir transforma uma
   * deslogada geral num soluco que ninguem percebe.
   */
  async forceRefresh(
    session: SsoSessionData,
    res: Response,
  ): Promise<SsoSessionData | null> {
    try {
      const tokens = await this.requestTokens({
        grant_type: 'refresh_token',
        refresh_token: session.refreshToken,
      });

      return this.sessions.write(res, tokens, session.csrfToken);
    } catch (error) {
      this.logger.warn(
        `renovacao forcada recusada pelo SSO: ${error instanceof Error ? error.message : String(error)}`,
      );

      this.sessions.clear(res);
      return null;
    }
  }
  async refreshIfNeeded(
    session: SsoSessionData,
    res: Response,
  ): Promise<SsoSessionData | null> {
    const now = Math.floor(Date.now() / 1000);

    if (session.expiresAt - now > this.refreshSkewSeconds) {
      return session;
    }

    try {
      const tokens = await this.requestTokens({
        grant_type: 'refresh_token',
        refresh_token: session.refreshToken,
      });

      // Mantem o token anti-CSRF: o front ja tem uma copia dele, e a
      // renovacao acontece sem ele saber.
      return this.sessions.write(res, tokens, session.csrfToken);
    } catch (error) {
      this.logger.warn(
        `renovacao recusada pelo SSO: ${error instanceof Error ? error.message : String(error)}`,
      );

      this.sessions.clear(res);
      return null;
    }
  }

  /**
   * Entrega o access token corrente ao cliente (RFC 10017 secao 6.2).
   *
   * Renova antes de entregar, se estiver perto de expirar, para o cliente
   * nunca receber um token quase morto. O refresh token NAO sai daqui: ele
   * fica na sessao, do lado do servidor. O cliente segura apenas uma
   * credencial de minutos, e volta aqui quando ela expira.
   */
  async currentAccessToken(
    req: Request,
    res: Response,
  ): Promise<{ access_token: string; token_type: 'Bearer'; expires_in: number }> {
    const stored = this.sessions.read(req);

    if (!stored) {
      throw new UnauthorizedException('sessao ausente ou invalida');
    }

    const session = await this.refreshIfNeeded(stored, res);

    if (!session) {
      throw new UnauthorizedException('sessao expirada; refaca o login');
    }

    return {
      access_token: session.accessToken,
      token_type: 'Bearer',
      expires_in: Math.max(
        0,
        session.expiresAt - Math.floor(Date.now() / 1000),
      ),
    };
  }

  /**
   * Encerra a sessao local E revoga o refresh token no SSO (RFC 7009).
   *
   * A revogacao nao e opcional. Com sessao client-side, limpar o cookie so
   * apaga a copia do navegador: qualquer outra copia continuaria renovando
   * indefinidamente. Revogar mata a familia inteira no servidor.
   *
   * O access token ja emitido segue valido ate expirar, o que e inerente a
   * token assinado e sem consulta. Por isso ele dura minutos, nao dias.
   */
  async logout(req: Request, res: Response): Promise<void> {
    const session = this.sessions.read(req);

    // Limpa os cookies antes de falar com o SSO: se a rede cair, o usuario
    // ainda sai localmente.
    this.sessions.clear(res);
    this.cookies.clear(res, SSO_TX_COOKIE, { sameSite: 'lax' });

    if (!session?.refreshToken) return;

    try {
      const { revocation_endpoint: revocationEndpoint } =
        await this.discovery.metadata();

      if (!revocationEndpoint) {
        this.logger.warn(
          'o SSO nao anuncia revocation_endpoint; o refresh token seguira valido ate expirar',
        );
        return;
      }

      await fetch(revocationEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          token: session.refreshToken,
          token_type_hint: 'refresh_token',
          client_id: this.clientId,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await this.assertions.build(),
        }),
      });
    } catch (error) {
      // Logout local ja aconteceu. Falhar aqui piora a seguranca, mas travar
      // o logout seria pior ainda.
      this.logger.error(
        `falha ao revogar o refresh token no SSO: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private async requestTokens(
    grant: Record<string, string>,
  ): Promise<SsoTokenResponse> {
    const { token_endpoint: tokenEndpoint } = await this.discovery.metadata();

    const res = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...grant,
        client_id: this.clientId,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await this.assertions.build(),
      }),
    });

    const body = (await res.json().catch(() => null)) as
      | (SsoTokenResponse & Partial<SsoTokenError>)
      | null;

    if (!res.ok || !body) {
      const detail = body?.error
        ? `${body.error}: ${body.error_description ?? ''}`.trim()
        : `HTTP ${res.status}`;

      // 5xx e falha do SSO; 4xx e recusa legitima da credencial.
      throw res.status >= 500
        ? new BadGatewayException(`SSO indisponivel (${detail})`)
        : new UnauthorizedException(`SSO recusou a troca (${detail})`);
    }

    if (!body.access_token || !body.refresh_token) {
      throw new BadGatewayException('resposta do SSO sem os tokens esperados');
    }

    return body;
  }

  private timingSafeEqual(a: string, b: string): boolean {
    const left = Buffer.from(a);
    const right = Buffer.from(b);

    return left.length === right.length && crypto.timingSafeEqual(left, right);
  }
}
