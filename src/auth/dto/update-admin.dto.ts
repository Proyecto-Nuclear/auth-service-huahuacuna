import { IsOptional, IsString, MinLength, MaxLength, IsEnum } from 'class-validator';
import { UserStatus } from '@prisma/client';

/**
 * DTO para actualizar administradores (RF-005)
 * Criterios de aceptación:
 * - Administradores pueden ser activados/desactivados
 * - Se puede actualizar nombre y estado
 */
export class UpdateAdminDto {
  @IsOptional()
  @IsString()
  @MinLength(3, { message: 'El nombre debe tener al menos 3 caracteres' })
  @MaxLength(100, { message: 'El nombre no puede tener más de 100 caracteres' })
  name?: string;

  @IsOptional()
  @IsEnum(UserStatus, { message: 'El estado debe ser válido' })
  status?: UserStatus;
}
