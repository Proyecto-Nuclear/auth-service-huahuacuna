import { IsEmail, IsEnum, IsString, Matches, MaxLength, MinLength } from "class-validator";
import { Role } from "@prisma/client";

/**
 * DTO para crear administradores (RF-005)
 * Criterios de aceptación:
 * - Solo super-admin puede crear administradores
 * - Formulario incluye: nombre, email, rol (ADMIN o SUPER_ADMIN)
 * - Administradores pueden ser activados/desactivados
 */
export class CreateAdminDto {
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

  @IsEnum(Role, { message: 'El rol debe ser ADMIN o SUPER_ADMIN' })
  role: Role;
}
