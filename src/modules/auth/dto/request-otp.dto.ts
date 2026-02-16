// import { IsEmail, IsEnum, IsString, Matches } from 'class-validator';
// import { ApiProperty } from '@nestjs/swagger';
// // import { OtpChannel } from 'src/common/enums/otp.enum';
// import { OtpChannel } from '@prisma/client';

// export class RequestOtpDto {
//   @ApiProperty({ example: '+2349063801889' })
//   @IsString()
//   // @IsEmail()
//   @Matches(/^\+?[1-9]\d{7,14}$/, {
//     message: 'Invalid phone number format',
//   })
//   identifier: string;

//   @ApiProperty({ enum: OtpChannel })
//   @IsEnum(OtpChannel)
//   channel: OtpChannel;
// }

import { IsEnum, IsEmail, Matches, ValidateIf } from 'class-validator';
import { OtpChannel } from '@prisma/client';
import { ApiProperty } from '@nestjs/swagger';

export class RequestOtpDto {
  @ApiProperty({ enum: OtpChannel })
  @IsEnum(OtpChannel)
  channel: OtpChannel;

  @ApiProperty({ example: '+2349063801889 or synapgrid@gmail.com' })
  @ValidateIf((o) => o.channel === OtpChannel.EMAIL)
  @IsEmail({}, { message: 'Invalid email format' })
  @ValidateIf((o) => o.channel === OtpChannel.PHONE)
  @Matches(/^\+\d{10,15}$/, {
    message: 'Invalid phone number format',
  })
  identifier: string;
}
