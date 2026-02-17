import {
  IsEnum,
  IsEmail,
  IsString,
  Matches,
  ValidateIf,
} from 'class-validator';
import { OtpChannel } from '@prisma/client';

export class LoginDto {
  @IsEnum(OtpChannel)
  channel: OtpChannel;

  @ValidateIf((o) => o.channel === OtpChannel.EMAIL)
  @IsEmail({}, { message: 'Invalid email format' })
  @ValidateIf((o) => o.channel === OtpChannel.PHONE)
  @Matches(/^\+\d{10,15}$/, {
    message: 'Invalid phone number format',
  })
  identifier: string;

  @IsString()
  password: string;
}
