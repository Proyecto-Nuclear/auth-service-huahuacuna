import { Controller, Logger } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { HealthCheckService, HealthCheck } from '@nestjs/terminus';
import { PrismaHealthIndicator } from './indicators/prisma-health.indicator.js';

/**
 * Health Check Controller - Auth Service
 * Responde a mensajes Kafka para health checks
 *
 * RF: Disponibilidad - Health Checks para microservicios
 * Topic: auth_health_check
 */
@Controller()
export class HealthController {
  private readonly logger = new Logger(HealthController.name);

  constructor(
    private readonly health: HealthCheckService,
    private readonly prisma: PrismaHealthIndicator,
  ) {}

  /**
   * Health Check endpoint via Kafka
   * Topic: auth_health_check
   *
   * Verifica:
   * - Conexión a PostgreSQL (Prisma)
   * - Estado general del servicio
   */
  @MessagePattern('auth_health_check')
  @HealthCheck()
  async check() {
    try {
      this.logger.debug('Health check requested via Kafka');

      const result = await this.health.check([
        // Verificar base de datos
        () => this.prisma.isHealthy('database'),
      ]);

      return {
        ...result,
        service: 'auth-service',
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error(`Health check failed: ${error.message}`);
      return {
        status: 'error',
        service: 'auth-service',
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Ping rápido sin verificar dependencias
   * Topic: auth_ping
   */
  @MessagePattern('auth_ping')
  ping() {
    return {
      status: 'ok',
      service: 'auth-service',
      timestamp: new Date().toISOString(),
    };
  }
}
