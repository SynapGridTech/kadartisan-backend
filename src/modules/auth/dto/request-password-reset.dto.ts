import { IsEnum, IsString } from 'class-validator';
import { OtpChannel } from '@prisma/client';
import { ApiProperty } from '@nestjs/swagger';

export class RequestPasswordResetDto {
  @ApiProperty({
    description:
      'The email address or phone number of the user requesting password reset',
    example: 'synapgrid@gmail.com',
  })
  @IsString()
  identifier: string;

  @ApiProperty()
  @IsEnum(OtpChannel)
  channel: OtpChannel;
}
