import { IsString, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateSkillDto {
  @ApiProperty({ example: 'Electrician', required: false })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({ example: 'Home Services', required: false })
  @IsString()
  @IsOptional()
  category?: string;
}
