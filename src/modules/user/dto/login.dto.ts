import {
  IsEnum,
  IsEmail,
  IsString,
  Matches,
  ValidateIf,
} from 'class-validator';
import { OtpChannel } from '@prisma/client';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'synapgrid@gmail.com' })
  @ValidateIf((o) => o.channel === OtpChannel.EMAIL)
  @IsEmail({}, { message: 'Invalid email format' })
  @ValidateIf((o) => o.channel === OtpChannel.PHONE)
  @Matches(/^\+\d{10,15}$/, {
    message: 'Invalid phone number format',
  })
  identifier: string;

  @ApiProperty({ example: 'Default$235' })
  @IsString()
  password: string;

  @ApiProperty({ example: 'EMAIL' })
  @IsEnum(OtpChannel)
  channel: OtpChannel;

}
