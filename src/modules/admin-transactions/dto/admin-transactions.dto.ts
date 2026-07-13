import { IsIn, IsInt, IsOptional, IsString, Min, IsNumber, IsNotEmpty } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional, ApiProperty } from '@nestjs/swagger';

export class ListTransactionsQueryDto {
  @ApiPropertyOptional({ enum: ['PENDING', 'SUCCESS', 'FAILED', 'STUCK', 'REVERSED'] })
  @IsIn(['PENDING', 'SUCCESS', 'FAILED', 'STUCK', 'REVERSED'])
  @IsOptional()
  status?: string;

  @ApiPropertyOptional({
    enum: ['PAYMENT', 'PAYOUT', 'REFUND', 'DEPOSIT', 'WITHDRAWAL', 'FEE'],
  })
  @IsIn(['PAYMENT', 'PAYOUT', 'REFUND', 'DEPOSIT', 'WITHDRAWAL', 'FEE'])
  @IsOptional()
  type?: string;

  @ApiPropertyOptional({ description: 'Search by reference or description' })
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

export class InitiateRefundDto {
  @ApiPropertyOptional({ example: 5000, description: 'Partial refund amount; omit for full refund' })
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @IsOptional()
  amount?: number;

  @ApiProperty({ example: 'Customer cancelled service' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}
