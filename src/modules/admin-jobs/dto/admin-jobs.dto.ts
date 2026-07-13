import { IsIn, IsInt, IsNotEmpty, IsOptional, IsString, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ListJobsQueryDto {
  @ApiPropertyOptional({ enum: ['PENDING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'] })
  @IsIn(['PENDING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'])
  @IsOptional()
  status?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  urgency?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  category?: string;

  @ApiPropertyOptional({ description: 'Search by title or description' })
  @IsString()
  @IsOptional()
  search?: string;

  @ApiPropertyOptional({ description: 'Cursor (job id) for pagination' })
  @IsString()
  @IsOptional()
  cursor?: string;

  @ApiPropertyOptional({ default: 20 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  limit?: number;
}

export class ReasonDto {
  @ApiProperty({ example: 'Client requested cancellation' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}

export class ResolveDisputeDto {
  @ApiProperty({ enum: ['artisan', 'customer'] })
  @IsIn(['artisan', 'customer'])
  outcome: 'artisan' | 'customer';

  @ApiProperty({ example: 'Evidence favored the artisan' })
  @IsString()
  @IsNotEmpty()
  notes: string;
}

export class NoteContentDto {
  @ApiProperty({ example: 'Requested more photos from customer' })
  @IsString()
  @IsNotEmpty()
  content: string;
}
