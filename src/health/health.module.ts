import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HealthController } from './health.controller.js';
import { PrismaHealthIndicator } from './indicators/prisma-health.indicator.js';
import { PrismaService } from '../auth/prisma.service.js';

/**
 * Health Module - Auth Service
 * Configura health checks para el microservicio de autenticación
 *
 * Health Checks incluidos:
 * - PostgreSQL connectivity (Prisma)
 */
@Module({
  imports: [TerminusModule],
  controllers: [HealthController],
  providers: [
    PrismaHealthIndicator,
    PrismaService,
  ],
})
export class HealthModule {}
