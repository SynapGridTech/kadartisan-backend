import {
  ArrayNotEmpty,
  IsArray,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// ---------- plans ----------
export class CreatePlanDto {
  @ApiProperty({ example: 'Pro' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ example: 'For growing artisans' })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({ example: 5000 })
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  price: number;

  @ApiPropertyOptional({ enum: ['MONTHLY', 'QUARTERLY', 'YEARLY'], default: 'MONTHLY' })
  @IsIn(['MONTHLY', 'QUARTERLY', 'YEARLY'])
  @IsOptional()
  interval?: 'MONTHLY' | 'QUARTERLY' | 'YEARLY';

  @ApiPropertyOptional({ example: ['Unlimited bids', 'Priority support'] })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  features?: string[];

  @ApiPropertyOptional({ example: 50 })
  @Type(() => Number)
  @IsInt()
  @IsOptional()
  jobLimit?: number;
}

export class UpdatePlanDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  name?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  description?: string;

  @ApiPropertyOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  @IsOptional()
  price?: number;

  @ApiPropertyOptional({ enum: ['MONTHLY', 'QUARTERLY', 'YEARLY'] })
  @IsIn(['MONTHLY', 'QUARTERLY', 'YEARLY'])
  @IsOptional()
  interval?: 'MONTHLY' | 'QUARTERLY' | 'YEARLY';

  @ApiPropertyOptional()
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  features?: string[];

  @ApiPropertyOptional()
  @Type(() => Number)
  @IsInt()
  @IsOptional()
  jobLimit?: number;
}

// ---------- subscribers ----------
export class ListSubscriptionsQueryDto {
  @ApiPropertyOptional({ enum: ['ACTIVE', 'CANCELLED', 'EXPIRED', 'PAST_DUE'] })
  @IsIn(['ACTIVE', 'CANCELLED', 'EXPIRED', 'PAST_DUE'])
  @IsOptional()
  status?: string;

  @ApiPropertyOptional({ description: 'Filter by plan id' })
  @IsString()
  @IsOptional()
  planId?: string;

  @ApiPropertyOptional({ description: 'Search by subscriber name/email' })
  @IsString()
  @IsOptional()
  search?: string;

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

export class ChangePlanDto {
  @ApiProperty({ description: 'Target plan id' })
  @IsString()
  @IsNotEmpty()
  planId: string;

  @ApiPropertyOptional({ description: 'Idempotency key' })
  @IsString()
  @IsOptional()
  idempotencyKey?: string;
}

export class CancelSubscriptionDto {
  @ApiPropertyOptional({ enum: ['immediate', 'end_of_period'], default: 'end_of_period' })
  @IsIn(['immediate', 'end_of_period'])
  @IsOptional()
  mode?: 'immediate' | 'end_of_period';

  @ApiPropertyOptional({ example: 'Customer request' })
  @IsString()
  @IsOptional()
  reason?: string;
}

export class ExtendSubscriptionDto {
  @ApiProperty({ example: 7, description: 'Complimentary days to add' })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  days: number;
}

export class WaivePaymentDto {
  @ApiProperty({ example: 'Goodwill credit' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}

export class SubscriptionNoteDto {
  @ApiProperty({ example: 'Discussed renewal by phone' })
  @IsString()
  @IsNotEmpty()
  content: string;
}

export class AssignPlanDto {
  @ApiProperty({ description: 'Plan id to assign' })
  @IsString()
  @IsNotEmpty()
  planId: string;

  @ApiPropertyOptional({ example: 30, description: 'Duration in days' })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  durationDays?: number;
}
