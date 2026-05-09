import { IsIn, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RespondAppealDto {
  @ApiProperty({ enum: ['APPROVED', 'REJECTED'], example: 'APPROVED' })
  @IsIn(['APPROVED', 'REJECTED'])
  @IsNotEmpty()
  status: 'APPROVED' | 'REJECTED';
}
