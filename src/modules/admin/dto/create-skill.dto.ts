import { IsString, IsOptional, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateSkillDto {
  @ApiProperty({ example: 'Electrician' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'Home Services', required: false })
  @IsString()
  @IsOptional()
  category?: string;
}
