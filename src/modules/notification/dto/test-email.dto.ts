import { IsEmail, IsOptional, IsString, MaxLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class TestEmailDto {
  @ApiProperty({ example: 'someone@example.com', description: 'Recipient email address' })
  @IsEmail()
  to: string;

  @ApiPropertyOptional({ example: 'Hello from KadArtisan' })
  @IsString()
  @IsOptional()
  @MaxLength(150)
  subject?: string;

  @ApiPropertyOptional({ example: 'Testing the mail pipeline.' })
  @IsString()
  @IsOptional()
  @MaxLength(2000)
  message?: string;
}
