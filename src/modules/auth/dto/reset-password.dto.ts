import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';
import Api from 'twilio/lib/rest/Api';

export class ResetPasswordDto {
  @ApiProperty({
    description: 'The temporary token sent to the user for password reset',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.NTEpMeJf36POk6yJV_adQssw5c',
  })
  @IsString()
  tempToken: string;

  @ApiProperty({
    description: 'The new password for the user',
    example: 'NewPassword$123',
  })
  @IsString()
  newPassword: string;

  @ApiProperty({
    description: 'The confirmation of the new password',
    example: 'NewPassword$123',
  })
  @IsString()
  confirmPassword: string;
}
