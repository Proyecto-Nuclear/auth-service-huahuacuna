import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { AuthController } from "./auth.controller.js";
import { AuthService } from "./auth.service.js";
import { AuditService, HashService, TokenService } from "./services/index.js";
import { EnvsConfig } from "../config/env.config.js";
import { PrismaService } from "./prisma.service.js";

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: EnvsConfig.JWT_SECRET,
      signOptions: {
        expiresIn: '24h',
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    HashService,
    TokenService,
    AuditService,
  ],
  exports: [AuthService, TokenService, HashService, AuditService]
})
export class AuthModule {}
