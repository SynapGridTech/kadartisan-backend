import { IsBoolean, IsEmail, IsIn, IsInt, IsNotEmpty, IsOptional, IsString, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AuthenticationSettingsDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  twoFactorEnabled: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  loginAlertsEnabled: boolean;

  @ApiProperty({ example: 'strong', description: 'Password policy identifier' })
  @IsString()
  passwordPolicy: string;
}

export class InviteAdminDto {
  @ApiProperty({ example: 'Jane Admin' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'jane@kadartisan.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'ADMIN' })
  @IsString()
  @IsNotEmpty()
  role: string;
}

export class UpdateAdminDto {
  @ApiPropertyOptional({ example: 'ADMIN' })
  @IsString()
  @IsOptional()
  role?: string;

  @ApiPropertyOptional({ enum: ['active', 'suspended'] })
  @IsIn(['active', 'suspended'])
  @IsOptional()
  status?: 'active' | 'suspended';
}

export class FirewallSettingsDto {
  @ApiProperty({ example: false })
  @IsBoolean()
  ipWhitelistEnabled: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  rateLimitEnabled: boolean;
}

export class AddFirewallIpDto {
  @ApiProperty({ example: '196.220.0.1' })
  @IsString()
  @IsNotEmpty()
  ip: string;

  @ApiPropertyOptional({ example: 'Head office' })
  @IsString()
  @IsOptional()
  label?: string;
}

export class DataProtectionDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  encryptionEnabled: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  gdprEnabled: boolean;

  @ApiProperty({ example: 'cloud' })
  @IsString()
  backupStorage: string;
}

export class AuditLogQueryDto {
  @ApiPropertyOptional({ default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page?: number;

  @ApiPropertyOptional({ default: 50 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  limit?: number;

  @ApiPropertyOptional({ description: 'ISO from date' })
  @IsString()
  @IsOptional()
  from?: string;

  @ApiPropertyOptional({ description: 'ISO to date' })
  @IsString()
  @IsOptional()
  to?: string;
}
