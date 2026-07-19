import { IsUUID, IsOptional, IsString, MinLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateConversationDto {
  @ApiProperty({
    example: 'b3f1c2d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d',
    description:
      "The other participant's User id. If the caller is a customer this is the artisan, and vice versa.",
  })
  @IsUUID()
  recipientUserId: string;

  @ApiPropertyOptional({
    example: 'b3f1c2d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d',
    description: 'Optional service request id that this thread is about.',
  })
  @IsUUID()
  @IsOptional()
  requestId?: string;

  @ApiPropertyOptional({
    example: 'Hi, are you available this weekend?',
    description: 'Optional first message to send when opening the thread.',
  })
  @IsString()
  @IsOptional()
  @MinLength(1)
  message?: string;
}
