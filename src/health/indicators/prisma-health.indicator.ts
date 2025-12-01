import { Injectable, Logger } from "@nestjs/common";
import { HealthCheckError, HealthIndicator, HealthIndicatorResult } from "@nestjs/terminus";
import { PrismaService } from "../../auth/prisma.service.js";

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
      await this.prisma.$queryRaw`SELECT 1`;
      this.logger.debug('Database health check passed');
      return this.getStatus(key, true, { message: 'PostgreSQL is healthy' });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Database health check failed: ${errorMessage}`);
      throw new HealthCheckError(
        'Database check failed',
        this.getStatus(key, false, {
          message: errorMessage,
          timestamp: new Date().toISOString(),
        }),
      );
    }
  }
}
