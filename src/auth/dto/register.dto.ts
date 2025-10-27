import { IsEmail, IsString, Matches, MaxLength, MinLength } from "class-validator";

/**
 * DTO para el registro de padrinos (RF-001)
 * Criterios de aceptación:
 * - Formulario contiene: nombre completo, email, teléfono, documento de identidad, dirección, contraseña
 * - Validación de email único
 * - Contraseña mínimo 8 caracteres con mayúsculas, minúsculas y números
 */
export class RegisterDto {
  @IsString()
  @MinLength(3, { message: 'El nombre debe tener al menos 3 caracteres' })
  @MaxLength(100, { message: 'El nombre no puede tener más de 100 caracteres' })
  name: string;

  @IsEmail({}, { message: 'El email debe ser válido' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message: 'La contraseña debe contener al menos una mayúscula, una minúscula y un número',
  })
  password: string;

  @IsString()
  @MinLength(7, { message: 'El teléfono debe tener al menos 7 caracteres' })
  @MaxLength(20, { message: 'El teléfono no puede tener más de 20 caracteres' })
  phone: string;

  @IsString()
  @MinLength(5, { message: 'El documento de identidad debe tener al menos 5 caracteres' })
  @MaxLength(20, { message: 'El documento de identidad no puede tener más de 20 caracteres' })
  documentId: string;

  @IsString()
  @MinLength(5, { message: 'La dirección debe tener al menos 5 caracteres' })
  @MaxLength(200, { message: 'La dirección no puede tener más de 200 caracteres' })
  address: string;
}
