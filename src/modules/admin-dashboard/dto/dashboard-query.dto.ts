import { IsIn, IsInt, IsOptional, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class MetricsQueryDto {
  @ApiPropertyOptional({
    example: '7d',
    enum: ['today', '7d', '30d'],
    default: '7d',
  })
  @IsIn(['today', '7d', '30d'])
  @IsOptional()
  period?: 'today' | '7d' | '30d';
}

export class ActivityQueryDto {
  @ApiPropertyOptional({ example: 6, default: 6, description: 'Max events to return' })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(50)
  @IsOptional()
  limit?: number;
}
