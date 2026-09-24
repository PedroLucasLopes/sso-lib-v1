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

@Controller('auth')
export class SsoAuthController {
  constructor(
    private oauth: SsoOAuthService,
    private sessions: SsoSessionService,
  ) {}

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

  @Post('logout')
  @SsoAuthenticated()
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.oauth.logout(req, res);
  }

  @Get('token')
  @SsoAuthenticated()
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

  @Get('me')
  @SsoAuthenticated()
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
