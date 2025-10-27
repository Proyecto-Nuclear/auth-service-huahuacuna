import { IsString } from 'class-validator';

/**
 * DTO para refrescar el access token
 */
export class RefreshTokenDto {
  @IsString()
  refreshToken: string;
}
