import { IsEmail } from 'class-validator';

/**
 * DTO para solicitar recuperación de contraseña (RF-003)
 * Usuario ingresa email registrado
 * Sistema envía link temporal de recuperación (válido 1 hora)
 */
export class ResetPasswordRequestDto {
  @IsEmail({}, { message: 'El email debe ser válido' })
  email: string;
}
