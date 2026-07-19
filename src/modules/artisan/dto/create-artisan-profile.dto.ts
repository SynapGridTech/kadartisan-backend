import {
  IsString,
  IsArray,
  IsOptional,
  MinLength,
  IsNumber,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateArtisanProfileDto {
  @ApiProperty({
    example: ['Plumbing', 'Carpentry'],
    description: 'Array of skill names the artisan offers',
  })
  @IsArray()
  @IsString({ each: true })
  skills: string[];

  @ApiProperty({
    example: 'Kaduna, Nigeria',
    description: 'Full location string matching interface specification',
  })
  @IsString()
  location: string;

  @ApiProperty({
    example: 'Master Plumber & Pipe Specialist',
    description: 'Short display headline/title shown under the artisan name',
    required: false,
  })
  @IsString()
  @IsOptional()
  headline?: string;

  @ApiProperty({
    example:
      'Experienced plumber with 10+ years of experience in residential and commercial plumbing',
    description: 'Artisan biography',
    required: false,
  })
  @IsString()
  @IsOptional()
  bio?: string;

  @ApiProperty({
    example: 'https://example.com/profile.jpg',
    description: 'Profile picture URL',
    required: false,
  })
  @IsString()
  @IsOptional()
  profilePicture?: string;

  @ApiProperty({
    example: ['https://example.com/cert1.pdf', 'https://example.com/cert2.pdf'],
    description: 'Verification document URLs',
    required: false,
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  verificationDocuments?: string[];

  @ApiProperty({
    example: 10,
    description: 'Years of professional experience',
    required: false,
  })
  @IsNumber()
  @IsOptional()
  yearsOfExperience?: number;

  // Keep state/lga for backward compatibility (auto-populated from location)
  @IsString()
  @IsOptional()
  state?: string;

  @IsString()
  @IsOptional()
  lga?: string;

  @IsString()
  @IsOptional()
  workshopAddress?: string;
}
