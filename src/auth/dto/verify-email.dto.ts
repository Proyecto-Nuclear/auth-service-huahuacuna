import { IsString } from 'class-validator';

/**
 * DTO para verificación de email
 * Token enviado por email al registrarse
 */
export class VerifyEmailDto {
  @IsString()
  token: string;
}
