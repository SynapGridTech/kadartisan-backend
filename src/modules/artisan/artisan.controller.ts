import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { ArtisanService } from './providers/artisan.service';
import { CreateArtisanProfileDto } from './dto/create-artisan-profile.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';

@ApiTags('Artisan')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('artisan')
export class ArtisanController {
  constructor(private readonly artisanService: ArtisanService) {}

  @Post('create-profile')
  @HttpCode(HttpStatus.CREATED)
  async createProfile(
    @Req() req: any,
    @Body() dto: CreateArtisanProfileDto,
  ) {
    return this.artisanService.createProfile(req.user.id, dto);
  }

  //__________ GET ARTISAN PROFILE ________________________
  @Get('profile')
  async getProfile(@Req() req: any) {
    return this.artisanService.getProfileByUserId(req.user.id);
  }

  //__________ REAPPLY FOR ARTISAN ________________________
  @Post('profile/reapply')
  @HttpCode(HttpStatus.CREATED)
  async reapply(@Req() req: any, @Body() dto: CreateArtisanProfileDto) {
    return this.artisanService.reapplyForArtisan(req.user.id, dto);
  }

  //__________ GET ALL SKILLS ________________________
  @Get('skills')
  async getAllSkills() {
    return this.artisanService.getAllSkills();
  }
}
