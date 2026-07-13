import { IsIn, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ListBadgesQueryDto {
  @ApiPropertyOptional({ enum: ['pending', 'active', 'revoked'] })
  @IsIn(['pending', 'active', 'revoked'])
  @IsOptional()
  status?: 'pending' | 'active' | 'revoked';

  @ApiPropertyOptional({ enum: ['verified', 'top_artisan'] })
  @IsIn(['verified', 'top_artisan'])
  @IsOptional()
  type?: 'verified' | 'top_artisan';

  @ApiPropertyOptional({ description: 'Search by artisan name' })
  @IsString()
  @IsOptional()
  search?: string;
}

export class ReviewBadgeDto {
  @ApiProperty({ enum: ['award', 'reject', 'hold'] })
  @IsIn(['award', 'reject', 'hold'])
  decision: 'award' | 'reject' | 'hold';

  @ApiProperty({ example: 'Documents verified' })
  @IsString()
  @IsNotEmpty()
  note: string;

  @ApiPropertyOptional({ example: 'Incomplete documents' })
  @IsString()
  @IsOptional()
  reason?: string;
}
