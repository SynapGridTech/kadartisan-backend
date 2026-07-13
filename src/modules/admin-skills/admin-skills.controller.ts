import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminSkillsService } from './providers/admin-skills.service';
import {
  CreateSkillCategoryDto,
  ListSkillsQueryDto,
  SkillFormDto,
  UpdateSkillFormDto,
  UpdateSkillStatusDto,
} from './dto/admin-skills.dto';

@ApiTags('Admin Skills')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin')
export class AdminSkillsController {
  constructor(private readonly service: AdminSkillsService) {}

  // ---------- skills ----------
  @Get('skills')
  @ApiOperation({ summary: 'List skills with search and category filter' })
  list(@Query() query: ListSkillsQueryDto) {
    return this.service.list(query);
  }

  @Get('skills/metrics')
  @ApiOperation({ summary: 'Skill assignment overview statistics' })
  metrics() {
    return this.service.metrics();
  }

  @Post('skills')
  @ApiOperation({ summary: 'Register a new skill' })
  create(@Body() dto: SkillFormDto) {
    return this.service.create(dto);
  }

  @Put('skills/:id')
  @ApiOperation({ summary: 'Edit skill descriptors and icons' })
  @ApiParam({ name: 'id', type: 'string' })
  update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateSkillFormDto) {
    return this.service.update(id, dto);
  }

  @Delete('skills/:id')
  @ApiOperation({ summary: 'Delete an unused skill' })
  @ApiParam({ name: 'id', type: 'string' })
  remove(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.remove(id);
  }

  @Patch('skills/:id/status')
  @ApiOperation({ summary: 'Update skill status (active/inactive)' })
  @ApiParam({ name: 'id', type: 'string' })
  setStatus(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateSkillStatusDto) {
    return this.service.setStatus(id, dto.status);
  }

  // ---------- categories ----------
  @Get('skill-categories')
  @ApiOperation({ summary: 'List parent occupational categories' })
  listCategories() {
    return this.service.listCategories();
  }

  @Post('skill-categories')
  @ApiOperation({ summary: 'Add a new occupational category' })
  createCategory(@Body() dto: CreateSkillCategoryDto) {
    return this.service.createCategory(dto);
  }
}
