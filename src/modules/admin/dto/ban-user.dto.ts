import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class BanUserDto {
  @ApiProperty({ example: 'Fraudulent activity detected' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}
