import { IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SendMessageDto {
  @ApiProperty({
    example: 'Sure, I can come by on Saturday morning.',
    description: 'Message body.',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(5000)
  body: string;
}
