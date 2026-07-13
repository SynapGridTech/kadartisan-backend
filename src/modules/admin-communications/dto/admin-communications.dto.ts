import {
  ArrayNotEmpty,
  IsArray,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class BroadcastDto {
  @ApiProperty({ example: 'System maintenance notice' })
  @IsString()
  @IsNotEmpty()
  subject: string;

  @ApiProperty({ example: 'The platform will be down from 2-3am.' })
  @IsString()
  @IsNotEmpty()
  body: string;

  @ApiProperty({ example: ['email', 'push'], description: 'Delivery channels' })
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  channels: string[];

  @ApiProperty({ example: 'all', description: 'Audience segment (all/artisans/customers)' })
  @IsString()
  @IsNotEmpty()
  audience: string;
}

export class EstimateQueryDto {
  @ApiPropertyOptional({ description: 'Comma-separated channels' })
  @IsString()
  @IsOptional()
  channels?: string;

  @ApiPropertyOptional({ description: 'Audience segment' })
  @IsString()
  @IsOptional()
  audience?: string;
}

export class TemplatesQueryDto {
  @ApiPropertyOptional({ enum: ['admin', 'system'] })
  @IsIn(['admin', 'system'])
  @IsOptional()
  type?: 'admin' | 'system';
}

export class CreateTemplateDto {
  @ApiProperty({ example: 'Welcome email' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ example: 'Welcome to KadArtisan' })
  @IsString()
  @IsOptional()
  subject?: string;

  @ApiProperty({ example: 'Hello {{name}}, welcome aboard!' })
  @IsString()
  @IsNotEmpty()
  body: string;

  @ApiProperty({ example: ['email'] })
  @IsArray()
  @IsString({ each: true })
  channels: string[];

  @ApiPropertyOptional({ enum: ['admin', 'system'], default: 'admin' })
  @IsIn(['admin', 'system'])
  @IsOptional()
  type?: 'admin' | 'system';
}

export class UpdateTemplateDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  name?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  subject?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  body?: string;

  @ApiPropertyOptional()
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  channels?: string[];
}

export class MessageLogQueryDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  channel?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  status?: string;

  @ApiPropertyOptional({ default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page?: number;

  @ApiPropertyOptional({ default: 20 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  limit?: number;
}
