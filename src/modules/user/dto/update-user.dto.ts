import { IsString, IsOptional, IsEmail, MinLength } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateUserDto {
  @ApiPropertyOptional({
    example: 'Amina Bello',
    description: 'Display name',
  })
  @IsString()
  @IsOptional()
  @MinLength(2)
  fullName?: string;

  @ApiPropertyOptional({
    example: 'amina@example.com',
    description: 'Email address',
  })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiPropertyOptional({
    example: 'https://example.com/avatar.jpg',
    description: 'Profile picture URL',
  })
  @IsString()
  @IsOptional()
  profilePicture?: string;

  // ----- Customer location / address (persisted on CustomerProfile) -----

  @ApiPropertyOptional({
    example: 'Kaduna, Nigeria',
    description: 'Full location string collected at registration',
  })
  @IsString()
  @IsOptional()
  location?: string;

  @ApiPropertyOptional({ example: 'Kaduna', description: 'State' })
  @IsString()
  @IsOptional()
  state?: string;

  @ApiPropertyOptional({ example: 'Chikun', description: 'Local government area' })
  @IsString()
  @IsOptional()
  lga?: string;

  @ApiPropertyOptional({
    example: '12 Ahmadu Bello Way',
    description: 'Street address',
  })
  @IsString()
  @IsOptional()
  address?: string;
}
