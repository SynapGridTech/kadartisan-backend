import { IsIn, IsInt, IsNotEmpty, IsOptional, IsString, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ListComplaintsQueryDto {
  @ApiPropertyOptional({ description: 'Status tab', enum: ['new', 'in_review', 'escalated', 'resolved', 'closed_invalid'] })
  @IsString()
  @IsOptional()
  tab?: string;

  @ApiPropertyOptional({ description: 'Filter by filer user id' })
  @IsString()
  @IsOptional()
  filedBy?: string;

  @ApiPropertyOptional({ description: 'Date range, e.g. 7d/30d' })
  @IsString()
  @IsOptional()
  dateRange?: string;

  @ApiPropertyOptional({ description: 'Search subject/description' })
  @IsString()
  @IsOptional()
  search?: string;

  @ApiPropertyOptional({ description: 'Cursor (complaint id)' })
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

export class ResolveComplaintDto {
  @ApiProperty({ example: 'refund_issued' })
  @IsString()
  @IsNotEmpty()
  outcome: string;

  @ApiProperty({ example: 'Customer refunded after review' })
  @IsString()
  @IsNotEmpty()
  notes: string;
}

export class CloseInvalidDto {
  @ApiProperty({ example: 'Duplicate complaint' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}

export class ComplaintNoteDto {
  @ApiProperty({ example: 'Contacted both parties for statements' })
  @IsString()
  @IsNotEmpty()
  content: string;
}

export class ResolveDisputePayloadDto {
  @ApiProperty({ enum: ['artisan', 'customer', 'split'] })
  @IsIn(['artisan', 'customer', 'split'])
  outcome: 'artisan' | 'customer' | 'split';

  @ApiPropertyOptional({ example: 5000, description: 'Amount to release/refund' })
  @Type(() => Number)
  @IsOptional()
  amount?: number;

  @ApiProperty({ example: 'Resolved after evidence review' })
  @IsString()
  @IsNotEmpty()
  notes: string;
}

export class AddDisputeEvidenceDto {
  @ApiProperty({ example: 'Chat transcript' })
  @IsString()
  @IsNotEmpty()
  label: string;

  @ApiPropertyOptional({ example: 'https://cdn.kadartisan.com/evidence/1.png' })
  @IsString()
  @IsOptional()
  url?: string;

  @ApiPropertyOptional({ example: 'Shows agreed scope' })
  @IsString()
  @IsOptional()
  note?: string;
}
