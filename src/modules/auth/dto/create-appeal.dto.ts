import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateAppealDto {
  @ApiProperty({ example: '+2348012345678', description: 'Phone number or email of the suspended account' })
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @ApiProperty({ example: 'I believe my suspension was a misunderstanding. I have corrected the issue.' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}
