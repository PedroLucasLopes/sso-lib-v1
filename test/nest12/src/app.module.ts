import { Module } from '@nestjs/common';
import type { DynamicModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SsoClientModule } from '@pedrolucaslopes/sso-client';
import type { SsoClientOptions } from '@pedrolucaslopes/sso-client';
import {
  OptionalController,
  PrivateController,
  PublicController,
  VisitorController,
} from './probe.controller';

@Module({})
export class AppModule {
  static register(options: SsoClientOptions): DynamicModule {
    return {
      module: AppModule,
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        SsoClientModule.forRoot(options),
      ],
      controllers: [
        PublicController,
        OptionalController,
        VisitorController,
        PrivateController,
      ],
    };
  }
}
