import { IsString, IsOptional, MinLength, MaxLength, IsUrl } from 'class-validator';

/**
 * DTO para actualización de perfil de padrino (RF-004)
 * Criterios de aceptación:
 * - Padrino puede actualizar: teléfono, dirección, foto de perfil
 * - No puede modificar: email, documento
 */
export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MinLength(7, { message: 'El teléfono debe tener al menos 7 caracteres' })
  @MaxLength(20, { message: 'El teléfono no puede tener más de 20 caracteres' })
  phone?: string;

  @IsOptional()
  @IsString()
  @MinLength(5, { message: 'La dirección debe tener al menos 5 caracteres' })
  @MaxLength(200, { message: 'La dirección no puede tener más de 200 caracteres' })
  address?: string;

  @IsOptional()
  @IsUrl({}, { message: 'La foto de perfil debe ser una URL válida' })
  avatar?: string;
}
