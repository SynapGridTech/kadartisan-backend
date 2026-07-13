import { IsString, IsOptional, IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class SearchArtisanDto {
  @ApiPropertyOptional({ example: 'Electrician', description: 'Skill name to filter by' })
  @IsString()
  @IsOptional()
  skill?: string;

  @ApiPropertyOptional({ example: 'Kaduna', description: 'Free-text location (matches state, lga or location)' })
  @IsString()
  @IsOptional()
  location?: string;

  @ApiPropertyOptional({ example: 'Kaduna', description: 'State to filter by' })
  @IsString()
  @IsOptional()
  state?: string;

  @ApiPropertyOptional({ example: 'Kaduna North', description: 'LGA to filter by' })
  @IsString()
  @IsOptional()
  lga?: string;

  @ApiPropertyOptional({ example: 1, description: 'Page number (1-based)', default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page?: number;
}
