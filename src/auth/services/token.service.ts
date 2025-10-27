import { Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Role, User } from "@prisma/client";
import { randomBytes } from "crypto";

/**
 * Payload del JWT
 */
export interface JwtPayload {
  sub: number; // User ID
  email: string;
  name: string;
  role: Role;
  iat?: number;
  exp?: number;
}

/**
 * Servicio para generación y validación de tokens JWT
 */
@Injectable()
export class TokenService {
  // Token de acceso: 24 horas (según RF-002)
  private readonly ACCESS_TOKEN_EXPIRATION = '24h';
  // Token de refresco: 7 días
  private readonly REFRESH_TOKEN_EXPIRATION = '7d';

  constructor(private readonly jwtService: JwtService) {}

  /**
   * Genera un access token JWT
   * @param user - Usuario para el cual generar el token
   * @returns Access token firmado
   */
  generateAccessToken(user: User): string {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    return this.jwtService.sign(payload, {
      expiresIn: this.ACCESS_TOKEN_EXPIRATION,
    });
  }

  /**
   * Genera un refresh token JWT
   * @param userId - ID del usuario
   * @returns Refresh token firmado
   */
  generateRefreshToken(userId: number): string {
    return this.jwtService.sign(
      { sub: userId },
      { expiresIn: this.REFRESH_TOKEN_EXPIRATION }
    );
  }

  /**
   * Verifica y decodifica un token JWT
   * @param token - Token a verificar
   * @returns Payload del token
   */
  verifyToken(token: string): JwtPayload {
    return this.jwtService.verify<JwtPayload>(token);
  }

  /**
   * Genera un token aleatorio seguro (para reset de contraseña, verificación de email)
   * @returns Token hexadecimal de 32 bytes
   */
  generateSecureToken(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Calcula la fecha de expiración para un token
   * @param hours - Horas hasta la expiración
   * @returns Fecha de expiración
   */
  getExpirationDate(hours: number): Date {
    const date = new Date();
    date.setHours(date.getHours() + hours);
    return date;
  }
}
