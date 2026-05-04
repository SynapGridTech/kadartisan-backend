import { IsString, IsNumber, IsOptional, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateServiceRequestDto {
  @ApiProperty({ example: 'Light Fixture Installation' })
  @IsString()
  title: string;

  @ApiProperty({ example: 'Need electrician to install new light fixtures in living room' })
  @IsString()
  description: string;

  @ApiProperty({  required: false })
  @IsOptional()
  image?: string;


  @ApiProperty({ example: 'Kaduna North', required: false })
  @IsString()
  @IsOptional()
  serviceLocation?: string;

  @ApiProperty({ example: 'Electrical Installation' })
  @IsString()
  skillRequired: string;

  @ApiProperty({ example: 5000.0, required: false })
  @IsNumber()
  @IsOptional()
  budget?: number;

  @ApiProperty({ example: 'URGENT', enum: ['URGENT', 'STANDARD', 'FLEXIBLE'], required: false })
  @IsString()
  @IsOptional()
  urgency?: string;

  @ApiProperty({ example: '+2348012345678', required: false })
  @IsString()
  @IsOptional()
  contactInfo?: string;
}
