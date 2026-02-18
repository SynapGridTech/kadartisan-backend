import { IsEmail, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CompleteRegistrationDto {
  @ApiProperty({ example: 'ahmad dogo' })
  @IsString()
  fullName: string;

  @ApiProperty({ example: '+234906380189' })
  @IsString()
  phoneNumber: string;

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
