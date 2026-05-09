import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  ParseIntPipe,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiParam, ApiBody } from '@nestjs/swagger';
import { ArtisanService } from './providers/artisan.service';
import { CreateArtisanProfileDto } from './dto/create-artisan-profile.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';

@ApiTags('Artisan')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard)
@Controller('artisan')
export class ArtisanController {
  constructor(private readonly artisanService: ArtisanService) {}

  @Post('create-profile')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create artisan profile (sets status to PENDING)' })
  async createProfile(
    @Req() req: any,
    @Body() dto: CreateArtisanProfileDto,
  ) {
    return this.artisanService.createProfile(req.user.id, dto);
  }

  //__________ GET ARTISAN PROFILE ________________________
  @Get('profile')
  @ApiOperation({ summary: 'Get current artisan profile' })
  async getProfile(@Req() req: any) {
    return this.artisanService.getProfileByUserId(req.user.id);
  }

  //__________ REAPPLY FOR ARTISAN ________________________
  @Post('profile/reapply')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Reapply for artisan after rejection' })
  public async reapply(@Req() req: any, @Body() dto: CreateArtisanProfileDto) {
    return this.artisanService.reapplyForArtisan(req.user.id, dto);
  }

  //__________ GET ALL APPROVED ARTISANS ________________________
  @Get('all-artisans')
  @ApiOperation({ summary: 'Get all approved artisans with profiles' })
  async getArtisans() {
    return this.artisanService.getArtisans();
  }

  //__________ GET ALL SKILLS ________________________
  @Get('skills')
  @ApiOperation({ summary: 'Get all available skills grouped by category' })
  async getAllSkills() {
    return this.artisanService.getAllSkills();
  }

  //__________ GET PENDING ARTISANS ________________________
  @Get('pending')
  @UseGuards(RolesGuard)
  @ApiOperation({ summary: 'Get all artisans with pending approval status' })
  @ApiResponse({ status: 200, description: 'List of pending artisans returned' })
  async getPendingArtisans() {
    return this.artisanService.getPendingArtisans();
  }

  //__________ SEARCH ARTISANS ________________________
  @Get('search')
  @ApiOperation({ summary: 'Search approved artisans by skill and location' })
  @ApiBody({
    description: 'Filters for artisan search',
    required: false,
    schema: {
      type: 'object',
      properties: {
        skill: { type: 'string', example: 'Electrician' },
        state: { type: 'string', example: 'Kaduna' },
        lga: { type: 'string', example: 'Kaduna North' },
      },
    },
  })
 public async searchArtisans(
    @Body() filters: {
      skill?: string;
      state?: string;
      lga?: string;
    },
  ) {
    return this.artisanService.searchArtisans(filters);
  }

  //__________ APPROVE ARTISAN ________________________
  @Patch(':id/approve')
  @UseGuards(RolesGuard)
  @ApiOperation({ summary: 'Approve a pending artisan application' })
  @ApiParam({ name: 'id', description: 'Artisan user ID', type: 'number', example: 1 })
  @ApiResponse({ status: 200, description: 'Artisan approved successfully' })
  @ApiResponse({ status: 400, description: 'Invalid artisan request' })
  async approveArtisan(@Param('id', ParseIntPipe) id: number) {
    return this.artisanService.approveArtisan(id);
  }

  //__________ REJECT ARTISAN ________________________
  @Patch(':id/reject')
  @UseGuards(RolesGuard)
  @ApiOperation({ summary: 'Reject a pending artisan application' })
  @ApiParam({ name: 'id', description: 'Artisan user ID', type: 'number', example: 1 })
  @ApiResponse({ status: 200, description: 'Artisan rejected successfully' })
  @ApiResponse({ status: 400, description: 'Invalid artisan request' })
  async rejectArtisan(@Param('id', ParseIntPipe) id: number, @Body('reason') reason?: string) {
    return this.artisanService.rejectArtisan(id, reason);
  }
}
