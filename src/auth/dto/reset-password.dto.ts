import { IsString, MinLength, Matches } from 'class-validator';

/**
 * DTO para confirmar reset de contraseña (RF-003)
 * Usuario puede establecer nueva contraseña
 * Contraseña anterior queda invalidada
 */
export class ResetPasswordDto {
  @IsString()
  token: string;

  @IsString()
  @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message: 'La contraseña debe contener al menos una mayúscula, una minúscula y un número',
  })
  newPassword: string;
}
