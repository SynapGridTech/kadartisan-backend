import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
} from '@nestjs/swagger';
import { Roles } from 'src/common/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Role } from '@prisma/client';
import { AdminService } from './providers/admin.service';
import { CreateSkillDto } from './dto/create-skill.dto';
import { UpdateSkillDto } from './dto/update-skill.dto';
import { SuspendUserDto } from './dto/suspend-user.dto';
import { BanUserDto } from './dto/ban-user.dto';
import { RespondAppealDto } from './dto/respond-appeal.dto';

@ApiTags('Admin')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  // ========== SKILL MANAGEMENT ==========

  //__________________ ROUTE TO GET LIST OF ALL SKILLS (ADMIN only)_________________
  @Get('skills')
  @ApiOperation({ summary: 'Get all skills grouped by category (admin view)' })
  @ApiResponse({ status: 200, description: 'Skills grouped by category returned' })
  async getAllSkills() {
    return this.adminService.getAllSkills();
  }

  //__________________ ROUTE TO CREATE A NEW SKILL (ADMIN only)_________________
  @Post('skills')
  @ApiOperation({ summary: 'Create a new skill' })
  @ApiResponse({ status: 201, description: 'Skill created successfully' })
  @ApiResponse({ status: 400, description: 'Skill already exists' })
  async createSkill(@Body() dto: CreateSkillDto) {
    return this.adminService.createSkill(dto.name, dto.category);
  }

  //__________________ ROUTE TO UPDATE A PARTICULAR SKILL (ADMIN only)_________________
  @Patch('skills/:id')
  @ApiOperation({ summary: 'Update an existing skill' })
  @ApiParam({ name: 'id', description: 'Skill ID', type: 'number', example: 1 })
  @ApiResponse({ status: 200, description: 'Skill updated successfully' })
  @ApiResponse({ status: 404, description: 'Skill not found' })
  @ApiResponse({ status: 400, description: 'Skill name already exists' })
  async updateSkill(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateSkillDto,
  ) {
    return this.adminService.updateSkill(id, dto.name, dto.category);
  }

  //__________________ ROUTE TO DELETE A  SKILLS (ADMIN only)_________________
  @Delete('skills/:id')
  @ApiOperation({ summary: 'Delete a skill' })
  @ApiParam({ name: 'id', description: 'Skill ID', type: 'number', example: 1 })
  @ApiResponse({ status: 200, description: 'Skill deleted successfully' })
  @ApiResponse({ status: 404, description: 'Skill not found' })
  async deleteSkill(@Param('id', ParseIntPipe) id: number) {
    return this.adminService.deleteSkill(id);
  }

  // ========== USER MODERATION ==========

  //__________________ ROUTE TO SUSPEND A USER (ADMIN only)_________________
  @Post('users/:id/suspend')
  @ApiOperation({ summary: 'Temporarily suspend a user' })
  @ApiParam({ name: 'id', description: 'User ID to suspend', type: 'number', example: 5 })
  @ApiResponse({ status: 200, description: 'User suspended successfully' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 400, description: 'User is banned or already suspended' })
  async suspendUser(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: SuspendUserDto,
  ) {
    return this.adminService.suspendUser(id, dto.days, dto.reason);
  }

  //__________________ ROUTE TO UN-SUSPEND A USER (ADMIN only)_________________
  @Post('users/:id/unsuspend')
  @ApiOperation({ summary: 'Lift a user suspension' })
  @ApiParam({ name: 'id', description: 'User ID to unsuspend', type: 'number', example: 5 })
  @ApiResponse({ status: 200, description: 'User suspension lifted successfully' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 400, description: 'User is not suspended' })
  async unsuspendUser(@Param('id', ParseIntPipe) id: number) {
    return this.adminService.unsuspendUser(id);
  }

  //__________________ ROUTE TO BAN A USER (ADMIN only)_________________
  @Post('users/:id/ban')
  @ApiOperation({ summary: 'Permanently ban a user' })
  @ApiParam({ name: 'id', description: 'User ID to ban', type: 'number', example: 5 })
  @ApiResponse({ status: 200, description: 'User banned successfully' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 400, description: 'User is already banned or is an admin' })
  async banUser(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: BanUserDto,
  ) {
    return this.adminService.banUser(id, dto.reason);
  }

  //__________________ ROUTE TO UN-BAN A USER (ADMIN only)_________________
  @Post('users/:id/unban')
  @ApiOperation({ summary: 'Lift a user ban' })
  @ApiParam({ name: 'id', description: 'User ID to unban', type: 'number', example: 5 })
  @ApiResponse({ status: 200, description: 'User ban lifted successfully' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 400, description: 'User is not banned' })
  async unbanUser(@Param('id', ParseIntPipe) id: number) {
    return this.adminService.unbanUser(id);
  }

  // ========== MODERATION LISTS & APPEALS ==========

  //__________________ ROUTE TO GET LIST OF SUSPENDED USERS (ADMIN only)_________________
  @Get('users/suspended')
  @ApiOperation({ summary: 'Get all currently suspended users' })
  @ApiResponse({ status: 200, description: 'List of suspended users returned' })
  async getSuspendedUsers() {
    return this.adminService.getSuspendedUsers();
  }

  //__________________ ROUTE TO GET LIST OF BANNED USERS (ADMIN only)_________________
  @Get('users/banned')
  @ApiOperation({ summary: 'Get all permanently banned users' })
  @ApiResponse({ status: 200, description: 'List of banned users returned' })
  async getBannedUsers() {
    return this.adminService.getBannedUsers();
  }

  //__________________ ROUTE TO GET A LIST OF ALL APPEALS (ADMIN only)_________________
  @Get('appeals')
  @ApiOperation({ summary: 'Get all user appeals' })
  @ApiResponse({ status: 200, description: 'List of appeals returned' })
  async getAppeals() {
    return this.adminService.getAppeals();
  }

  //__________________ ROUTE TO RESPOND TO AN APPEAL (ADMIN only)_________________
  @Post('appeals/:id/respond')
  @ApiOperation({ summary: 'Approve or reject a user appeal' })
  @ApiParam({ name: 'id', description: 'Appeal ID', type: 'number', example: 1 })
  @ApiResponse({ status: 200, description: 'Appeal responded to successfully' })
  @ApiResponse({ status: 404, description: 'Appeal not found' })
  @ApiResponse({ status: 400, description: 'Appeal already processed' })
  async respondToAppeal(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: RespondAppealDto,
  ) {
    return this.adminService.respondToAppeal(id, dto.status);
  }
}
