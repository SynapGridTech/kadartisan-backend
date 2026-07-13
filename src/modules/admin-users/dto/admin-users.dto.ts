import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateNoteDto {
  @ApiProperty({ example: 'Called customer to confirm identity.' })
  @IsString()
  @IsNotEmpty()
  content: string;
}

export class SoftDeleteUserDto {
  @ApiProperty({ example: 'John Doe', description: 'Full name confirmation for safety' })
  @IsString()
  @IsNotEmpty()
  confirmName: string;
}

export class MessageUserDto {
  @ApiProperty({ example: 'Please update your profile picture.' })
  @IsString()
  @IsNotEmpty()
  content: string;
}

export class UserControlsDto {
  @ApiProperty({ example: true, description: 'Whether the profile is publicly visible' })
  @IsBoolean()
  profileVisible: boolean;
}

export class FlagUserDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  flagged: boolean;

  @ApiPropertyOptional({ example: 'Suspicious activity reported' })
  @IsString()
  @IsOptional()
  reason?: string;
}

export class RevokeVerificationDto {
  @ApiProperty({ example: 'Documents found to be invalid' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}
