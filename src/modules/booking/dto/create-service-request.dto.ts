import { IsString, IsNumber, IsOptional, IsArray } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateServiceRequestDto {
  @ApiProperty({ example: 'Electrical Services', description: 'Service category matching interface specification' })
  @IsString()
  category: string;

  @ApiProperty({ example: 'Need electrician to install new light fixtures in living room' })
  @IsString()
  description: string;

  @ApiProperty({ example: 'Kaduna North, Kaduna', description: 'Location of service request' })
  @IsString()
  location: string;

  @ApiProperty({ example: 5000.0, required: false, description: 'Budget for the service' })
  @IsNumber()
  @IsOptional()
  budget?: number;

  @ApiProperty({ 
    example: ['Electrical', 'Wiring'], 
    description: 'Array of preferred skills required for this job',
    required: false 
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  preferredSkills?: string[];

  // Optional additional fields
  @ApiProperty({ example: 'Light Fixture Installation', required: false })
  @IsString()
  @IsOptional()
  title?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  image?: string;

  @ApiProperty({ example: 'URGENT', enum: ['URGENT', 'STANDARD', 'FLEXIBLE'], required: false })
  @IsString()
  @IsOptional()
  urgency?: string;

  @ApiProperty({ example: '+2348012345678', required: false })
  @IsString()
  @IsOptional()
  contactInfo?: string;
}