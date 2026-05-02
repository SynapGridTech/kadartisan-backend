import { IsString, IsArray, IsOptional, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateArtisanProfileDto {
  @ApiProperty({ 
    example: ['Plumbing', 'Carpentry'],
    description: 'Array of skill names the artisan offers',
  })
  @IsArray()
  @IsString({ each: true })
  skills: string[];

  @ApiProperty({ 
    example: 'Kaduna',
    description: 'State where the artisan operates',
  })
  @IsString()
  state: string;

  @ApiProperty({ 
    example: 'Birnin Gwari',
    description: 'Local Government Area',
    required: false,
  })
  @IsString()
  @IsOptional()
  lga?: string;

  @ApiProperty({ 
    example: 'No. 15 Sabuwar Kasuwa, Birnin Gwari',
    description: 'Workshop or business address (optional)',
    required: false,
  })
  @IsString()
  @IsOptional()
  workshopAddress?: string;
}
