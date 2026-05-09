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

@ApiTags('Admin')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  // ========== SKILL MANAGEMENT ==========

  @Get('skills')
  @ApiOperation({ summary: 'Get all skills grouped by category (admin view)' })
  @ApiResponse({ status: 200, description: 'Skills grouped by category returned' })
  async getAllSkills() {
    return this.adminService.getAllSkills();
  }

  @Post('skills')
  @ApiOperation({ summary: 'Create a new skill' })
  @ApiResponse({ status: 201, description: 'Skill created successfully' })
  @ApiResponse({ status: 400, description: 'Skill already exists' })
  async createSkill(@Body() dto: CreateSkillDto) {
    return this.adminService.createSkill(dto.name, dto.category);
  }

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

  @Delete('skills/:id')
  @ApiOperation({ summary: 'Delete a skill' })
  @ApiParam({ name: 'id', description: 'Skill ID', type: 'number', example: 1 })
  @ApiResponse({ status: 200, description: 'Skill deleted successfully' })
  @ApiResponse({ status: 404, description: 'Skill not found' })
  async deleteSkill(@Param('id', ParseIntPipe) id: number) {
    return this.adminService.deleteSkill(id);
  }
}
