import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { AuditAction, Role, User, UserStatus } from "@prisma/client";
import {
  CreateAdminDto,
  LoginDto,
  LoginResponseDto,
  RefreshTokenDto,
  RegisterDto,
  ResetPasswordDto,
  ResetPasswordRequestDto,
  UpdateAdminDto,
  UpdateProfileDto,
  VerifyEmailDto,
} from "./dto/index.js";
import { PrismaService } from "./prisma.service.js";
import { AuditService, HashService, TokenService } from "./services/index.js";

/**
 * Servicio principal de autenticación
 * Implementa todos los requisitos funcionales RF-001 a RF-005
 */
@Injectable()
export class AuthService {
  // Configuración según RF-002
  private readonly MAX_FAILED_ATTEMPTS = 5;
  private readonly LOCK_DURATION_MINUTES = 15;
  private readonly RESET_TOKEN_EXPIRATION_HOURS = 1;

  constructor(
    private readonly prisma: PrismaService,
    private readonly hashService: HashService,
    private readonly tokenService: TokenService,
    private readonly auditService: AuditService,
  ) {}

  /**
   * RF-001: Registro de Padrinos
   * Criterios:
   * - Email único
   * - Contraseña mínimo 8 caracteres con mayúsculas, minúsculas y números
   * - Email de confirmación enviado
   * - Usuario creado en estado "pendiente de activación"
   */
  async register(dto: RegisterDto, ipAddress?: string, userAgent?: string): Promise<{ message: string; userId: number }> {
    // Verificar email único
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      throw new ConflictException('El email ya está registrado');
    }

    // Verificar documento único
    if (dto.documentId) {
      const existingDocument = await this.prisma.user.findUnique({
        where: { documentId: dto.documentId },
      });

      if (existingDocument) {
        throw new ConflictException('El documento de identidad ya está registrado');
      }
    }

    // Hashear contraseña
    const hashedPassword = await this.hashService.hashPassword(dto.password);

    // Generar token de verificación de email
    const emailVerificationToken = this.tokenService.generateSecureToken();

    // Crear usuario en estado PENDING_ACTIVATION
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        password: hashedPassword,
        phone: dto.phone,
        documentId: dto.documentId,
        address: dto.address,
        role: Role.PADRINO,
        status: UserStatus.PENDING_ACTIVATION,
        emailVerificationToken,
        emailVerified: false,
      },
    });

    // Registrar auditoría
    await this.auditService.log({
      action: AuditAction.USER_CREATED,
      userId: user.id,
      ipAddress,
      userAgent,
      metadata: {
        email: user.email,
        role: user.role,
      },
    });

    // TODO: Enviar email de verificación con emailVerificationToken
    // Esto se implementará cuando se configure el servicio de email

    return {
      message: 'Usuario registrado exitosamente. Por favor verifica tu email.',
      userId: user.id,
    };
  }

  /**
   * RF-002: Autenticación de Usuarios
   * Criterios:
   * - Login exitoso redirige al dashboard correspondiente
   * - Credenciales incorrectas muestran mensaje de error
   * - Máximo 5 intentos fallidos bloquean cuenta temporalmente (15 min)
   * - Token JWT generado con expiración de 24h
   */
  async login(dto: LoginDto, ipAddress?: string, userAgent?: string): Promise<LoginResponseDto> {
    // Buscar usuario
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      await this.auditService.log({
        action: AuditAction.LOGIN_FAILED,
        ipAddress,
        userAgent,
        metadata: { email: dto.email, reason: 'Usuario no encontrado' },
      });
      throw new UnauthorizedException('Credenciales inválidas');
    }

    // Verificar si la cuenta está bloqueada
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const minutesRemaining = Math.ceil(
        (user.lockedUntil.getTime() - Date.now()) / (1000 * 60)
      );
      throw new ForbiddenException(
        `Cuenta bloqueada temporalmente. Intenta nuevamente en ${minutesRemaining} minuto(s).`
      );
    }

    // Verificar contraseña
    const isPasswordValid = await this.hashService.comparePassword(
      dto.password,
      user.password
    );

    if (!isPasswordValid) {
      // Incrementar contador de intentos fallidos
      await this.handleFailedLogin(user, ipAddress, userAgent);
      throw new UnauthorizedException('Credenciales inválidas');
    }

    // Verificar estado de la cuenta
    if (user.status === UserStatus.SUSPENDED) {
      throw new ForbiddenException('Tu cuenta ha sido suspendida. Contacta al administrador.');
    }

    if (user.status === UserStatus.INACTIVE) {
      throw new ForbiddenException('Tu cuenta está inactiva. Contacta al administrador.');
    }

    // Verificar email verificado
    if (!user.emailVerified) {
      throw new ForbiddenException(
        'Debes verificar tu email antes de iniciar sesión. Revisa tu bandeja de entrada.'
      );
    }

    // Login exitoso: resetear contador de intentos fallidos y actualizar última conexión
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginCount: 0,
        lockedUntil: null,
        lastLoginAt: new Date(),
      },
    });

    // Generar tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user.id);

    // Guardar refresh token en base de datos
    const refreshTokenExpiration = this.tokenService.getExpirationDate(24 * 7); // 7 días
    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt: refreshTokenExpiration,
      },
    });

    // Registrar auditoría
    await this.auditService.log({
      action: AuditAction.LOGIN_SUCCESS,
      userId: user.id,
      ipAddress,
      userAgent,
    });

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status,
        avatar: user.avatar ?? undefined,
        emailVerified: user.emailVerified,
      },
    };
  }

  /**
   * Maneja los intentos fallidos de login
   * Implementa el sistema de bloqueo temporal (RF-002)
   */
  private async handleFailedLogin(user: User, ipAddress?: string, userAgent?: string): Promise<void> {
    const newFailedCount = user.failedLoginCount + 1;
    let lockedUntil: Date | null = null;

    // Si alcanza el máximo de intentos, bloquear cuenta
    if (newFailedCount >= this.MAX_FAILED_ATTEMPTS) {
      lockedUntil = new Date();
      lockedUntil.setMinutes(lockedUntil.getMinutes() + this.LOCK_DURATION_MINUTES);
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginCount: newFailedCount,
        lockedUntil,
      },
    });

    await this.auditService.log({
      action: AuditAction.LOGIN_FAILED,
      userId: user.id,
      ipAddress,
      userAgent,
      metadata: {
        failedAttempts: newFailedCount,
        locked: !!lockedUntil,
      },
    });
  }

  /**
   * Verifica el email del usuario
   */
  async verifyEmail(dto: VerifyEmailDto): Promise<{ message: string }> {
    const user = await this.prisma.user.findFirst({
      where: { emailVerificationToken: dto.token },
    });

    if (!user) {
      throw new BadRequestException('Token de verificación inválido o expirado');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationToken: null,
        status: UserStatus.ACTIVE,
      },
    });

    await this.auditService.log({
      action: AuditAction.EMAIL_VERIFIED,
      userId: user.id,
    });

    return { message: 'Email verificado exitosamente. Ya puedes iniciar sesión.' };
  }

  /**
   * RF-003: Recuperación de Contraseña - Solicitud
   * Criterios:
   * - Usuario ingresa email registrado
   * - Sistema envía link temporal de recuperación (válido 1 hora)
   */
  async requestPasswordReset(dto: ResetPasswordRequestDto): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    // Por seguridad, siempre devolver el mismo mensaje
    // (no revelar si el email existe o no)
    const message = 'Si el email existe, recibirás instrucciones para restablecer tu contraseña.';

    if (!user) {
      return { message };
    }

    // Generar token de reset
    const resetToken = this.tokenService.generateSecureToken();
    const resetExpires = this.tokenService.getExpirationDate(this.RESET_TOKEN_EXPIRATION_HOURS);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordToken: resetToken,
        resetPasswordExpires: resetExpires,
      },
    });

    await this.auditService.log({
      action: AuditAction.PASSWORD_RESET,
      userId: user.id,
      metadata: { step: 'requested' },
    });

    // TODO: Enviar email con link de recuperación
    // Link: /reset-password?token={resetToken}

    return { message };
  }

  /**
   * RF-003: Recuperación de Contraseña - Confirmación
   * Criterios:
   * - Usuario puede establecer nueva contraseña
   * - Contraseña anterior queda invalidada
   */
  async resetPassword(dto: ResetPasswordDto): Promise<{ message: string }> {
    const user = await this.prisma.user.findFirst({
      where: {
        resetPasswordToken: dto.token,
        resetPasswordExpires: {
          gt: new Date(), // Token no expirado
        },
      },
    });

    if (!user) {
      throw new BadRequestException('Token de recuperación inválido o expirado');
    }

    // Hashear nueva contraseña
    const hashedPassword = await this.hashService.hashPassword(dto.newPassword);

    // Actualizar contraseña e invalidar token
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetPasswordToken: null,
        resetPasswordExpires: null,
        failedLoginCount: 0, // Resetear intentos fallidos
        lockedUntil: null, // Desbloquear cuenta si estaba bloqueada
      },
    });

    // Revocar todos los refresh tokens existentes
    await this.prisma.refreshToken.deleteMany({
      where: { userId: user.id },
    });

    await this.auditService.log({
      action: AuditAction.PASSWORD_RESET,
      userId: user.id,
      metadata: { step: 'completed' },
    });

    return { message: 'Contraseña restablecida exitosamente' };
  }

  /**
   * Refresca el access token usando un refresh token válido
   */
  async refreshAccessToken(dto: RefreshTokenDto): Promise<{ accessToken: string }> {
    // Verificar refresh token
    let payload: any;
    try {
      payload = this.tokenService.verifyToken(dto.refreshToken);
    } catch {
      throw new UnauthorizedException('Refresh token inválido');
    }

    // Verificar que el token existe en la base de datos y no ha sido revocado
    const tokenRecord = await this.prisma.refreshToken.findFirst({
      where: {
        token: dto.refreshToken,
        userId: payload.sub,
        revokedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: true,
      },
    });

    if (!tokenRecord) {
      throw new UnauthorizedException('Refresh token inválido o revocado');
    }

    // Generar nuevo access token
    const accessToken = this.tokenService.generateAccessToken(tokenRecord.user);

    return { accessToken };
  }

  /**
   * Cierra sesión revocando el refresh token
   */
  async logout(refreshToken: string, userId: number): Promise<{ message: string }> {
    await this.prisma.refreshToken.updateMany({
      where: {
        token: refreshToken,
        userId,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    await this.auditService.log({
      action: AuditAction.LOGOUT,
      userId,
    });

    return { message: 'Sesión cerrada exitosamente' };
  }

  /**
   * RF-004: Gestión de Perfil de Padrino
   * Criterios:
   * - Padrino puede actualizar: teléfono, dirección, foto de perfil
   * - No puede modificar: email, documento
   */
  async updateProfile(userId: number, dto: UpdateProfileDto): Promise<User> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    // Solo padrinos pueden actualizar su perfil con este endpoint
    // (los admins tienen su propio endpoint)
    if (user.role !== Role.PADRINO) {
      throw new ForbiddenException('Este endpoint es solo para padrinos');
    }

    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        phone: dto.phone,
        address: dto.address,
        avatar: dto.avatar,
      },
    });

    await this.auditService.log({
      action: AuditAction.USER_UPDATED,
      userId,
      performedBy: userId,
      metadata: {
        updatedFields: Object.keys(dto),
      },
    });

    return updatedUser;
  }

  /**
   * RF-005: Gestión de Administradores - Creación
   * Criterios:
   * - Solo super-admin puede crear administradores
   * - Administradores creados en estado ACTIVE
   */
  async createAdmin(
    dto: CreateAdminDto,
    createdBy: number,
    ipAddress?: string,
    userAgent?: string
  ): Promise<Omit<User, 'password'>> {
    // Verificar que quien crea es un super-admin
    const creator = await this.prisma.user.findUnique({
      where: { id: createdBy },
    });

    if (!creator || creator.role !== Role.SUPER_ADMIN) {
      throw new ForbiddenException('Solo super-admins pueden crear administradores');
    }

    // Verificar email único
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      throw new ConflictException('El email ya está registrado');
    }

    // Hashear contraseña
    const hashedPassword = await this.hashService.hashPassword(dto.password);

    // Crear administrador en estado ACTIVE y email ya verificado
    const admin = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        password: hashedPassword,
        role: dto.role,
        status: UserStatus.ACTIVE,
        emailVerified: true, // Los admins no necesitan verificar email
        createdById: createdBy,
      },
    });

    await this.auditService.log({
      action: AuditAction.ADMIN_CREATED,
      userId: admin.id,
      performedBy: createdBy,
      ipAddress,
      userAgent,
      metadata: {
        email: admin.email,
        role: admin.role,
      },
    });

    // Omitir password de la respuesta
    const { password, ...adminWithoutPassword } = admin;
    return adminWithoutPassword;
  }

  /**
   * RF-005: Gestión de Administradores - Actualización
   * Criterios:
   * - Administradores pueden ser activados/desactivados
   * - Se puede actualizar nombre y estado
   */
  async updateAdmin(
    adminId: number,
    dto: UpdateAdminDto,
    updatedBy: number
  ): Promise<Omit<User, 'password'>> {
    // Verificar que quien actualiza es un super-admin
    const updater = await this.prisma.user.findUnique({
      where: { id: updatedBy },
    });

    if (!updater || updater.role !== Role.SUPER_ADMIN) {
      throw new ForbiddenException('Solo super-admins pueden actualizar administradores');
    }

    // Verificar que el admin a actualizar existe
    const admin = await this.prisma.user.findUnique({
      where: { id: adminId },
    });

    if (!admin) {
      throw new NotFoundException('Administrador no encontrado');
    }

    // No se puede actualizar a sí mismo
    if (admin.id === updatedBy) {
      throw new ForbiddenException('No puedes actualizar tu propio estado');
    }

    // Solo se pueden actualizar admins
    if (admin.role === Role.PADRINO) {
      throw new ForbiddenException('Este endpoint es solo para administradores');
    }

    const updatedAdmin = await this.prisma.user.update({
      where: { id: adminId },
      data: {
        name: dto.name,
        status: dto.status,
      },
    });

    await this.auditService.log({
      action: AuditAction.USER_UPDATED,
      userId: adminId,
      performedBy: updatedBy,
      metadata: {
        updatedFields: Object.keys(dto),
        newStatus: dto.status,
      },
    });

    if (dto.status === UserStatus.INACTIVE || dto.status === UserStatus.SUSPENDED) {
      await this.auditService.log({
        action: dto.status === UserStatus.INACTIVE ? AuditAction.USER_DEACTIVATED : AuditAction.USER_SUSPENDED,
        userId: adminId,
        performedBy: updatedBy,
      });
    } else if (dto.status === UserStatus.ACTIVE) {
      await this.auditService.log({
        action: AuditAction.USER_ACTIVATED,
        userId: adminId,
        performedBy: updatedBy,
      });
    }

    const { password, ...adminWithoutPassword } = updatedAdmin;
    return adminWithoutPassword;
  }

  /**
   * Obtiene el perfil de un usuario por ID
   */
  async getUserById(userId: number): Promise<Omit<User, 'password'>> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  /**
   * Lista todos los administradores (solo para super-admin)
   */
  async listAdmins(requesterId: number) {
    const requester = await this.prisma.user.findUnique({
      where: { id: requesterId },
    });

    if (!requester || requester.role !== Role.SUPER_ADMIN) {
      throw new ForbiddenException('Solo super-admins pueden listar administradores');
    }

    return this.prisma.user.findMany({
      where: {
        role: {
          in: [Role.ADMIN, Role.SUPER_ADMIN],
        },
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        lastLoginAt: true,
        createdAt: true,
        createdBy: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
  }
}
