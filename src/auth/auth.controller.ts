import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service.js';
import {
  RegisterDto,
  LoginDto,
  VerifyEmailDto,
  ResetPasswordRequestDto,
  ResetPasswordDto,
  RefreshTokenDto,
  UpdateProfileDto,
  CreateAdminDto,
  UpdateAdminDto,
} from './dto/index.js';

/**
 * Helper para formatear errores de manera consistente
 */
function formatError(error: unknown) {
  if (error instanceof Error) {
    return {
      error: true,
      message: error.message,
      statusCode: (error as any).status || 500,
    };
  }
  return {
    error: true,
    message: 'Error desconocido',
    statusCode: 500,
  };
}

/**
 * Controlador de autenticación - Microservicio Kafka
 * Escucha mensajes de Kafka y ejecuta la lógica de negocio
 */
@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * RF-001: Registro de Padrinos
   * Topic: auth_register
   */
  @MessagePattern('auth_register')
  async register(@Payload() data: { dto: RegisterDto; ipAddress?: string; userAgent?: string }) {
    try {
      return await this.authService.register(data.dto, data.ipAddress, data.userAgent);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * RF-002: Autenticación de Usuarios
   * Topic: auth_login
   */
  @MessagePattern('auth_login')
  async login(@Payload() data: { dto: LoginDto; ipAddress?: string; userAgent?: string }) {
    try {
      return await this.authService.login(data.dto, data.ipAddress, data.userAgent);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * Verificación de email
   * Topic: auth_verify_email
   */
  @MessagePattern('auth_verify_email')
  async verifyEmail(@Payload() dto: VerifyEmailDto) {
    try {
      return await this.authService.verifyEmail(dto);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * RF-003: Recuperación de Contraseña - Solicitud
   * Topic: auth_request_password_reset
   */
  @MessagePattern('auth_request_password_reset')
  async requestPasswordReset(@Payload() dto: ResetPasswordRequestDto) {
    try {
      return await this.authService.requestPasswordReset(dto);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * RF-003: Recuperación de Contraseña - Confirmación
   * Topic: auth_reset_password
   */
  @MessagePattern('auth_reset_password')
  async resetPassword(@Payload() dto: ResetPasswordDto) {
    try {
      return await this.authService.resetPassword(dto);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * Refrescar access token
   * Topic: auth_refresh_token
   */
  @MessagePattern('auth_refresh_token')
  async refreshToken(@Payload() dto: RefreshTokenDto) {
    try {
      return await this.authService.refreshAccessToken(dto);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * Cerrar sesión
   * Topic: auth_logout
   */
  @MessagePattern('auth_logout')
  async logout(@Payload() data: { refreshToken: string; userId: number }) {
    try {
      return await this.authService.logout(data.refreshToken, data.userId);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * RF-004: Gestión de Perfil de Padrino
   * Topic: auth_update_profile
   */
  @MessagePattern('auth_update_profile')
  async updateProfile(@Payload() data: { userId: number; dto: UpdateProfileDto }) {
    try {
      return await this.authService.updateProfile(data.userId, data.dto);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * RF-005: Gestión de Administradores - Creación
   * Topic: auth_create_admin
   */
  @MessagePattern('auth_create_admin')
  async createAdmin(
    @Payload() data: {
      dto: CreateAdminDto;
      createdBy: number;
      ipAddress?: string;
      userAgent?: string;
    }
  ) {
    try {
      return await this.authService.createAdmin(
        data.dto,
        data.createdBy,
        data.ipAddress,
        data.userAgent
      );
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * RF-005: Gestión de Administradores - Actualización
   * Topic: auth_update_admin
   */
  @MessagePattern('auth_update_admin')
  async updateAdmin(
    @Payload() data: {
      adminId: number;
      dto: UpdateAdminDto;
      updatedBy: number;
    }
  ) {
    try {
      return await this.authService.updateAdmin(data.adminId, data.dto, data.updatedBy);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * Obtener usuario por ID
   * Topic: auth_get_user
   */
  @MessagePattern('auth_get_user')
  async getUserById(@Payload() data: { userId: number }) {
    try {
      return await this.authService.getUserById(data.userId);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * RF-005: Listar administradores
   * Topic: auth_list_admins
   */
  @MessagePattern('auth_list_admins')
  async listAdmins(@Payload() data: { requesterId: number }) {
    try {
      return await this.authService.listAdmins(data.requesterId);
    } catch (error) {
      return formatError(error);
    }
  }

  /**
   * Test endpoint para verificar comunicación
   * Topic: auth_test
   */
  @MessagePattern('auth_test')
  test() {
    return {
      message: 'Auth service is running successfully',
      timestamp: new Date().toISOString(),
    };
  }
}
