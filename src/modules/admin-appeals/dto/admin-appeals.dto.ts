import { IsIn, IsInt, IsNotEmpty, IsOptional, IsString, Min, IsBooleanString } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ListAppealsQueryDto {
  @ApiPropertyOptional({ enum: ['pending', 'in_review'] })
  @IsIn(['pending', 'in_review'])
  @IsOptional()
  tab?: 'pending' | 'in_review';

  @ApiPropertyOptional({ enum: ['suspension', 'verification', 'payout_hold'] })
  @IsIn(['suspension', 'verification', 'payout_hold'])
  @IsOptional()
  type?: 'suspension' | 'verification' | 'payout_hold';

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  search?: string;

  @ApiPropertyOptional({ description: 'Only urgent appeals' })
  @IsBooleanString()
  @IsOptional()
  urgent?: string;

  @ApiPropertyOptional({ default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page?: number;

  @ApiPropertyOptional({ default: 10 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  limit?: number;
}

export class AppealDecisionDto {
  @ApiProperty({ enum: ['approved', 'denied'] })
  @IsIn(['approved', 'denied'])
  decision: 'approved' | 'denied';

  @ApiProperty({ example: 'Your appeal has been reviewed and approved.' })
  @IsString()
  @IsNotEmpty()
  responseText: string;

  @ApiProperty({ example: 'Verified identity via support ticket #1023' })
  @IsString()
  @IsNotEmpty()
  adminNote: string;
}

export class EscalateAppealDto {
  @ApiProperty({ example: 'Requires senior review due to conflicting evidence' })
  @IsString()
  @IsNotEmpty()
  note: string;
}
