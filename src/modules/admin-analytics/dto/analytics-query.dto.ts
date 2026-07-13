import { IsBooleanString, IsIn, IsOptional } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class AnalyticsQueryDto {
  @ApiPropertyOptional({
    example: '30d',
    enum: ['7d', '30d', '90d'],
    default: '30d',
  })
  @IsIn(['7d', '30d', '90d'])
  @IsOptional()
  period?: '7d' | '30d' | '90d';

  @ApiPropertyOptional({
    example: 'true',
    description: 'Include comparison against previous period',
  })
  @IsBooleanString()
  @IsOptional()
  compare?: string;
}
