import { IsString, IsInt, IsNotEmpty, IsPositive } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SuspendUserDto {
  @ApiProperty({ example: 7, description: 'Number of days to suspend the user for' })
  @IsInt()
  @IsPositive()
  days: number;

  @ApiProperty({ example: 'Repeated policy violations' })
  @IsString()
  @IsNotEmpty()
  reason: string;
}
