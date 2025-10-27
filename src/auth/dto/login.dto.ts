import { IsEmail, IsString } from 'class-validator';

/**
 * DTO para la autenticación de usuarios (RF-002)
 * Login con credenciales (email/contraseña)
 */
export class LoginDto {
  @IsEmail({}, { message: 'El email debe ser válido' })
  email: string;

  @IsString()
  password: string;
}
