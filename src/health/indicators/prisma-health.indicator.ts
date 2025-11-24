import { Injectable, Logger } from '@nestjs/common';
import { HealthIndicator, HealthIndicatorResult, HealthCheckError } from '@nestjs/terminus';
import { PrismaService } from '../../auth/prisma.service.js';

/**
 * Prisma Health Indicator
 * Verifica la conectividad con PostgreSQL mediante Prisma
 */
@Injectable()
export class PrismaHealthIndicator extends HealthIndicator {
  private readonly logger = new Logger(PrismaHealthIndicator.name);

  constructor(private readonly prisma: PrismaService) {
    super();
  }

  /**
   * Verifica si la base de datos PostgreSQL está disponible
   * Ejecuta una query simple: SELECT 1
   */
  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      // Ejecutar query simple para verificar conexión
      await this.prisma.$queryRaw`SELECT 1`;

      this.logger.debug('Database health check passed');
      return this.getStatus(key, true, {
        message: 'PostgreSQL is healthy',
      });
    } catch (error) {
      this.logger.error(`Database health check failed: ${error.message}`);
      throw new HealthCheckError(
        'Database check failed',
        this.getStatus(key, false, {
          message: error.message,
          timestamp: new Date().toISOString(),
        }),
      );
    }
  }
}
