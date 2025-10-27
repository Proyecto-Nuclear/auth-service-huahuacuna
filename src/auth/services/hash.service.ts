import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

/**
 * Servicio para el hash y verificación de contraseñas
 * Utiliza bcrypt con 10 rounds de salt
 */
@Injectable()
export class HashService {
  private readonly SALT_ROUNDS = 10;

  /**
   * Hashea una contraseña en texto plano
   * @param password - Contraseña en texto plano
   * @returns Promise con el hash de la contraseña
   */
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }

  /**
   * Verifica que una contraseña coincida con un hash
   * @param password - Contraseña en texto plano
   * @param hash - Hash de la contraseña
   * @returns Promise<boolean> - true si coinciden
   */
  async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}
