import { IsBoolean, IsIn, IsInt, IsNotEmpty, IsOptional, IsString, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// ---------- FAQs ----------
export class FaqSearchQueryDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  search?: string;

  @ApiPropertyOptional({ default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page?: number;
}

export class CreateFaqDto {
  @ApiProperty({ example: 'How do I reset my password?' })
  @IsString()
  @IsNotEmpty()
  question: string;

  @ApiProperty({ example: 'Use the forgot-password link on login.' })
  @IsString()
  @IsNotEmpty()
  answer: string;
}

export class PublishFaqDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  published: boolean;
}

// ---------- Knowledge base ----------
export class KnowledgeSearchQueryDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  search?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  category?: string;
}

export class CreateArticleDto {
  @ApiProperty({ example: 'Handling refunds' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiPropertyOptional({ example: 'Steps for issuing refunds' })
  @IsString()
  @IsOptional()
  summary?: string;

  @ApiProperty({ example: 'Full article body...' })
  @IsString()
  @IsNotEmpty()
  content: string;

  @ApiPropertyOptional({ example: 'Payments' })
  @IsString()
  @IsOptional()
  category?: string;
}

export class UpdateArticleDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  title?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  summary?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  content?: string;
}

// ---------- Support tickets ----------
export class TicketQueryDto {
  @ApiPropertyOptional({ enum: ['Open', 'In Progress', 'Resolved'] })
  @IsIn(['Open', 'In Progress', 'Resolved'])
  @IsOptional()
  status?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  priority?: string;

  @ApiPropertyOptional({ default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page?: number;
}

export class UpdateTicketStatusDto {
  @ApiProperty({ enum: ['Open', 'In Progress', 'Resolved'] })
  @IsIn(['Open', 'In Progress', 'Resolved'])
  status: 'Open' | 'In Progress' | 'Resolved';
}

export class ReplyTicketDto {
  @ApiProperty({ example: 'Thanks for reaching out, we are on it.' })
  @IsString()
  @IsNotEmpty()
  message: string;
}
