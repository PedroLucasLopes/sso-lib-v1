import { Controller, Get, Req } from '@nestjs/common';
import type { Request } from 'express';
import {
  CurrentToken,
  CurrentUser,
  SsoAuthenticated,
  SsoOptional,
  SsoPublic,
} from '@pedrolucaslopes/sso-client';
import type { SsoUser } from '@pedrolucaslopes/sso-client';

@Controller('public')
export class PublicController {
  @Get('cookies')
  @SsoPublic()
  cookies(@Req() req: Request): { cookies: unknown } {
    return { cookies: req.cookies ?? null };
  }
}

@Controller('optional')
export class OptionalController {
  @Get()
  @SsoOptional()
  visit(
    @CurrentUser() user: SsoUser | undefined,
    @CurrentToken() token: string | undefined,
  ): { user: SsoUser | null; token: string | null } {
    return { user: user ?? null, token: token ?? null };
  }
}

@Controller('visitor')
@SsoOptional()
export class VisitorController {
  @Get()
  visit(@CurrentUser() user: SsoUser | undefined): { user: SsoUser | null } {
    return { user: user ?? null };
  }
}

@Controller('private')
export class PrivateController {
  @Get()
  @SsoAuthenticated()
  visit(@CurrentUser() user: SsoUser): { user: SsoUser } {
    return { user };
  }
}
