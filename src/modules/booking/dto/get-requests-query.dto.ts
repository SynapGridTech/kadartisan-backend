import { IsString, IsOptional, IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class GetRequestsQueryDto {
  @ApiPropertyOptional({
    example: 'OPEN',
    description: 'Filter by request status',
    enum: ['OPEN', 'ACCEPTED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'],
  })
  @IsString()
  @IsOptional()
  status?: string;

  @ApiPropertyOptional({ example: 1, description: 'Page number (1-based)', default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page?: number;
}
