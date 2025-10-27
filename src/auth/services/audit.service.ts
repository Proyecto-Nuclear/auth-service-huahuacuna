import { Injectable } from "@nestjs/common";
import { AuditAction } from "@prisma/client";
import { PrismaService } from "../prisma.service.js";

/**
 * Contexto para crear un log de auditoría
 */
export interface AuditContext {
  action: AuditAction;
  userId?: number; // Usuario afectado
  performedBy?: number; // Usuario que realizó la acción
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
}

/**
 * Servicio para gestión de auditoría (RF-005)
 * Registra todas las acciones importantes del sistema
 */
@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Crea un registro de auditoría
   * @param context - Contexto de la auditoría
   */
  async log(context: AuditContext): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          action: context.action,
          userId: context.userId,
          performedBy: context.performedBy,
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          metadata: context.metadata || {},
        },
      });
    } catch (error) {
      // Si falla el log de auditoría, no queremos detener la operación
      // pero lo registramos en consola
      console.error('Error logging audit:', error);
    }
  }

  /**
   * Obtiene los logs de auditoría de un usuario específico
   * @param userId - ID del usuario
   * @param limit - Límite de registros (default: 50)
   */
  async getUserAuditLogs(userId: number, limit: number = 50) {
    return this.prisma.auditLog.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: {
        performer: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
          },
        },
      },
    });
  }

  /**
   * Obtiene los logs de auditoría realizados por un administrador
   * @param performedBy - ID del administrador
   * @param limit - Límite de registros (default: 50)
   */
  async getPerformedAuditLogs(performedBy: number, limit: number = 50) {
    return this.prisma.auditLog.findMany({
      where: { performedBy },
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
          },
        },
      },
    });
  }

  /**
   * Obtiene logs de auditoría filtrados por acción
   * @param action - Tipo de acción
   * @param limit - Límite de registros (default: 100)
   */
  async getAuditLogsByAction(action: AuditAction, limit: number = 100) {
    return this.prisma.auditLog.findMany({
      where: { action },
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
          },
        },
        performer: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
          },
        },
      },
    });
  }
}
