import { IsBoolean, IsEmail, IsIn, IsNotEmpty, IsNumber, IsOptional, IsString, IsArray } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// ---------- 13 payment gateways ----------
export class UpdateGatewayDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  apiKey?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  secretKey?: string;

  @ApiPropertyOptional()
  @IsEmail()
  @IsOptional()
  merchantEmail?: string;

  @ApiPropertyOptional()
  @IsBoolean()
  @IsOptional()
  testMode?: boolean;
}

export class ToggleGatewayDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  active: boolean;
}

export class FeeStructureDto {
  @ApiProperty({ example: 10 })
  @Type(() => Number)
  @IsNumber()
  commissionRate: number;

  @ApiProperty({ enum: ['percentage', 'flat'], example: 'percentage' })
  @IsIn(['percentage', 'flat'])
  commissionType: string;

  @ApiProperty({ example: 100 })
  @Type(() => Number)
  @IsNumber()
  minimumFee: number;

  @ApiProperty({ example: true })
  @IsBoolean()
  withdrawalFeeEnabled: boolean;
}

export class PayoutSettingsDto {
  @ApiProperty({ example: 'weekly' })
  @IsString()
  payoutSchedule: string;

  @ApiProperty({ example: 5000 })
  @Type(() => Number)
  @IsNumber()
  minimumThreshold: number;

  @ApiProperty({ example: true })
  @IsBoolean()
  autoPayoutEnabled: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  holdEscrowEnabled: boolean;
}

export class CurrencySettingsDto {
  @ApiProperty({ example: 'NGN' })
  @IsString()
  baseCurrency: string;

  @ApiProperty({ example: ['NGN', 'USD'] })
  @IsArray()
  @IsString({ each: true })
  supportedCurrencies: string[];

  @ApiProperty({ example: 100 })
  @Type(() => Number)
  @IsNumber()
  minTransaction: number;

  @ApiProperty({ example: 5000000 })
  @Type(() => Number)
  @IsNumber()
  maxTransaction: number;
}

export class WebhookSettingsDto {
  @ApiProperty()
  @IsString()
  successUrl: string;

  @ApiProperty()
  @IsString()
  failedUrl: string;

  @ApiProperty()
  @IsString()
  completedUrl: string;

  @ApiProperty()
  @IsString()
  webhookSecret: string;
}

export class TestWebhookDto {
  @ApiProperty({ enum: ['success', 'failed', 'completed'] })
  @IsIn(['success', 'failed', 'completed'])
  event: 'success' | 'failed' | 'completed';
}

// ---------- 14 general settings ----------
export class PlatformSettingsDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  allowRegistration: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  requireEmailVerification: boolean;

  @ApiProperty({ example: false })
  @IsBoolean()
  maintenanceMode: boolean;

  @ApiProperty({ example: 10 })
  @Type(() => Number)
  @IsNumber()
  commissionRate: number;

  @ApiProperty({ enum: ['percentage', 'flat'], example: 'percentage' })
  @IsIn(['percentage', 'flat'])
  commissionType: string;
}

export class BusinessSettingsDto {
  @ApiProperty({ example: 'KadArtisan Ltd' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'hello@kadartisan.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: '+2348012345678' })
  @IsString()
  phone: string;

  @ApiProperty({ example: '12 Ahmadu Bello Way, Kaduna' })
  @IsString()
  address: string;
}

export class NotificationsConfigDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  emailNotifications: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  pushNotifications: boolean;

  @ApiProperty({ example: false })
  @IsBoolean()
  smsNotifications: boolean;
}

export class LocalizationDto {
  @ApiProperty({ example: 'en' })
  @IsString()
  defaultLanguage: string;

  @ApiProperty({ example: 'NGN' })
  @IsString()
  currency: string;

  @ApiProperty({ example: 'Africa/Lagos' })
  @IsString()
  timeZone: string;
}

export class DataSettingsDto {
  @ApiProperty({ example: 'daily' })
  @IsString()
  autoBackup: string;

  @ApiProperty({ example: true })
  @IsBoolean()
  anonymousUsage: boolean;
}
