import { Role, UserStatus } from '@prisma/client';

/**
 * DTO de respuesta para login exitoso (RF-002)
 * Incluye token JWT con expiración de 24h
 */
export class LoginResponseDto {
  accessToken: string;
  refreshToken: string;
  user: {
    id: number;
    email: string;
    name: string;
    role: Role;
    status: UserStatus;
    avatar?: string;
    emailVerified: boolean;
  };
}
