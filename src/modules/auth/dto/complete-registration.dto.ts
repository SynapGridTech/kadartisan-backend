import { IsEmail, IsString, MinLength, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CompleteRegistrationDto {
  @ApiProperty({ example: 'ahmad dogo' })
  @IsString()
  fullName: string;

  @ApiProperty({ example: '+234906380189', description: 'Phone number (syncs with interface.phone field)' })
  @IsString()
  phoneNumber: string;

  @ApiProperty({ example: '+234906380189', description: 'Optional phone field matching interface specification', required: false })
  @IsString()
  @IsOptional()
  phone?: string;

  @ApiProperty({ example: 'https://example.com/profile.jpg', description: 'Profile picture URL matching interface', required: false })
  @IsString()
  @IsOptional()
  profilePicture?: string;

  @ApiProperty({ example: 'Default$235' })
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'synapgrid@gmail.com' })
  @IsEmail()
  email?: string;

  @IsString()
  @ApiProperty({ example: 'ARTISAN, USER' })
  role?: string;

  @ApiProperty({ example: 'Default$235' })
  @MinLength(6)
  confirmPassword: string;

  @ApiProperty()
  @IsString()
  tempToken: string;
}