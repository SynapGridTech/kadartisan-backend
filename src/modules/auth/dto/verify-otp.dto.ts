import { IsEnum, IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { OtpChannel } from '@prisma/client';

export class VerifyOtpDto {
  @ApiProperty({ example: '+2349063801889' })
  @IsString()
  identifier: string;

  @ApiProperty({ example: '658820' })
  @IsString()
  @Length(6, 6)
  otp: string;

  @ApiProperty({ example: 'Phone Number , Email , Whatsapp' })
  @IsEnum(OtpChannel)
  channel: OtpChannel;
}
