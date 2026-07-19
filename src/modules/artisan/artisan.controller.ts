import {
  Controller,
  Post,
  Get,
  Patch,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Param,
  Query,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiParam,
} from '@nestjs/swagger';
import { ArtisanService } from './providers/artisan.service';
import { CreateArtisanProfileDto } from './dto/create-artisan-profile.dto';
import { SearchArtisanDto } from './dto/search-artisan.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@ApiTags('Artisan')
@Controller('artisan')
export class ArtisanController {
  constructor(private readonly artisanService: ArtisanService) {}

  // ========== ARTISAN PROFILE (Artisans only) ==========

  @Post('create-profile')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ARTISAN)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Submit artisan profile for verification (sets status to PENDING)',
  })
  async createProfile(@Req() req: any, @Body() dto: CreateArtisanProfileDto) {
    return this.artisanService.createProfile(req.user.id, dto);
  }

  //__________ GET ARTISAN PROFILE ________________________
  @Get('profile')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ARTISAN)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: "Get current artisan's complete profile" })
  async getProfile(@Req() req: any) {
    return this.artisanService.getProfileByUserId(req.user.id);
  }

  //__________ REAPPLY FOR ARTISAN ________________________
  @Post('profile/reapply')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ARTISAN)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Reapply for verification after rejection' })
  public async reapply(@Req() req: any, @Body() dto: CreateArtisanProfileDto) {
    return this.artisanService.reapplyForArtisan(req.user.id, dto);
  }

  //__________ GET ARTISAN WALLET (artisan) ________________________
  @Get('wallet')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ARTISAN)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: "Get the current artisan's wallet balance and recent transactions",
  })
  public async getWallet(@Req() req: any) {
    return this.artisanService.getWallet(req.user.id);
  }

  // ========== DISCOVERY & SEARCH (Public) ==========

  //__________ GET ALL SKILLS ________________________
  @Get('skills')
  @ApiOperation({ summary: 'Get all available skills grouped by category' })
  async getAllSkills() {
    return this.artisanService.getAllSkills();
  }

  //__________ GET ALL APPROVED ARTISANS ________________________
  @Get('all-artisans')
  @ApiOperation({ summary: 'Get all approved and active artisans' })
  async getArtisans() {
    return this.artisanService.getArtisans();
  }

  //__________ SEARCH ARTISANS ________________________
  @Get('search')
  @ApiOperation({
    summary: 'Search and filter approved artisans by skill and location',
  })
  public async searchArtisans(@Query() filters: SearchArtisanDto) {
    return this.artisanService.searchArtisans(filters);
  }

  //__________ VIEW PUBLIC ARTISAN PROFILE (counts a profile view) ________________________
  @Get(':id/public')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary:
      "View an artisan's public profile; increments profile views (self-views excluded)",
  })
  @ApiParam({
    name: 'id',
    description: 'Artisan user ID (UUID)',
    type: 'string',
  })
  public async viewPublicProfile(
    @Req() req: any,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.artisanService.viewPublicProfile(id, req.user?.id);
  }

  // ========== ADMIN-ONLY ARTISAN MANAGEMENT ==========

  //__________ GET PENDING ARTISANS ________________________
  @Get('pending')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Get all artisans with pending approval status' })
  @ApiResponse({
    status: 200,
    description: 'List of pending artisans returned',
  })
  async getPendingArtisans() {
    return this.artisanService.getPendingArtisans();
  }

  //__________ APPROVE ARTISAN ________________________
  @Post(':id/approve')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Approve a pending artisan application' })
  @ApiParam({
    name: 'id',
    description: 'Artisan user ID (UUID)',
    type: 'string',
  })
  @ApiResponse({ status: 200, description: 'Artisan approved successfully' })
  @ApiResponse({ status: 400, description: 'Invalid artisan request' })
  async approveArtisan(@Param('id', ParseUUIDPipe) id: string) {
    return this.artisanService.approveArtisan(id);
  }

  //__________ REJECT ARTISAN ________________________
  @Post(':id/reject')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Reject a pending artisan application' })
  @ApiParam({
    name: 'id',
    description: 'Artisan user ID (UUID)',
    type: 'string',
  })
  @ApiResponse({ status: 200, description: 'Artisan rejected successfully' })
  @ApiResponse({ status: 400, description: 'Invalid artisan request' })
  async rejectArtisan(
    @Param('id', ParseUUIDPipe) id: string,
    @Body('reason') reason?: string,
  ) {
    return this.artisanService.rejectArtisan(id, reason);
  }

  //__________ APPROVE ARTISAN (KYC PATCH alias — section 5.1) ________________________
  @Patch(':id/approve')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Approve artisan KYC submission (PATCH alias)' })
  @ApiParam({
    name: 'id',
    description: 'Artisan user ID (UUID)',
    type: 'string',
  })
  @ApiResponse({ status: 200, description: 'Artisan approved successfully' })
  async approveArtisanKyc(@Param('id', ParseUUIDPipe) id: string) {
    return this.artisanService.approveArtisan(id);
  }

  //__________ REJECT ARTISAN (KYC PATCH alias — section 5.1) ________________________
  @Patch(':id/reject')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Reject artisan KYC submission (PATCH alias)' })
  @ApiParam({
    name: 'id',
    description: 'Artisan user ID (UUID)',
    type: 'string',
  })
  @ApiResponse({ status: 200, description: 'Artisan rejected successfully' })
  async rejectArtisanKyc(
    @Param('id', ParseUUIDPipe) id: string,
    @Body('reason') reason?: string,
  ) {
    return this.artisanService.rejectArtisan(id, reason);
  }
}
