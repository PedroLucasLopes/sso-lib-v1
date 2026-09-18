import {
  Controller,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import {
  CurrentUser,
  SsoAuthenticated,
  SsoFreshGrant,
  SsoLogin,
} from '../decorator/ssoAccess.decorator';
import type { SsoMe, SsoUser } from '../dto/ssoSession.dto';
import { SsoOAuthService } from '../service/ssoOAuth.service';
import { SsoSessionService } from '../service/ssoSession.service';

/**
 * Rotas de autenticacao montadas automaticamente pelo modulo em `/auth`.
 * A aplicacao que consome a biblioteca nao precisa escrever nenhuma delas.
 */
@Controller('auth')
export class SsoAuthController {
  constructor(
    private oauth: SsoOAuthService,
    private sessions: SsoSessionService,
  ) {}

  /**
   * Inicia o login. Com sessao valida ja existente, volta direto para a
   * aplicacao em vez de reiniciar o fluxo.
   */
  @Get('login')
  @SsoLogin()
  async login(
    @Req() req: Request,
    @Res() res: Response,
    @Query('returnTo') returnTo?: string,
  ): Promise<void> {
    const existing = this.sessions.read(req);

    if (existing && existing.expiresAt > Math.floor(Date.now() / 1000)) {
      res.redirect(this.oauth.safeReturnTo(returnTo));
      return;
    }

    await this.oauth.beginLogin(res, returnTo);
  }

  @Get('callback')
  @SsoLogin()
  async callback(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.oauth.completeLogin(
      req,
      res,
      req.query,
    );
  }

  /** Encerra so a sessao local. A sessao no SSO continua de pe. */
  @Post('logout')
  @SsoAuthenticated()
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.oauth.logout(req, res);
  }

  /**
   * Entrega o access token corrente (RFC 10017 secao 6.2.2.1, "check session").
   *
   * Quem tem a sessao pega o token aqui e passa a usar `Authorization: Bearer`
   * nas chamadas seguintes. O refresh token NAO sai: fica no servidor, ligado
   * a sessao (secao 6.2.2.2). O cliente segura credencial de minutos e volta
   * aqui quando ela expira.
   */
  @Get('token')
  @SsoAuthenticated()
  // Quem pega o token vai usa-lo como Bearer: ele sai com o papel de agora.
  @SsoFreshGrant()
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  @Header('Pragma', 'no-cache')
  async token(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ access_token: string; token_type: 'Bearer'; expires_in: number }> {
    return this.oauth.currentAccessToken(req, res);
  }

  /**
   * Identidade, permissoes e token anti-CSRF do usuario corrente.
   *
   * E o que a interface chama logo depois do login: com isto ela monta o menu
   * e ja fica com o valor que precisa devolver no header `X-CSRF-Token` nas
   * requisicoes que mudam estado. O mesmo valor tambem chega pelo cookie
   * legivel `app_csrf`; os dois caminhos existem para o front escolher.
   */
  @Get('me')
  @SsoAuthenticated()
  // A tela consulta esta rota justamente para saber o que mudou no SSO: ela
  // pergunta a cada chamada, sem esperar a janela de `grantCheckSeconds`.
  @SsoFreshGrant()
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  me(@Req() req: Request, @CurrentUser() user: SsoUser): SsoMe {
    const session = this.sessions.read(req);

    return {
      ...user,
      csrfToken: session?.csrfToken ?? '',
      csrfCookieName: this.sessions.csrfCookieName,
    };
  }
}
