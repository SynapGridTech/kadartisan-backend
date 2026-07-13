import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminDashboardService } from './providers/admin-dashboard.service';
import { ActivityQueryDto, MetricsQueryDto } from './dto/dashboard-query.dto';

@ApiTags('Admin Dashboard')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/dashboard')
export class AdminDashboardController {
  constructor(private readonly dashboardService: AdminDashboardService) {}

  //__________ ATTENTION & ACTIONS NEEDED ________________________
  @Get('attention')
  @ApiOperation({ summary: 'Attention & actions needed panel' })
  @ApiResponse({ status: 200, description: 'Attention metrics returned' })
  async getAttention() {
    return this.dashboardService.getAttention();
  }

  //__________ PLATFORM KPIs ________________________
  @Get('metrics')
  @ApiOperation({ summary: 'Platform KPIs for users, revenue & jobs' })
  @ApiResponse({ status: 200, description: 'Metrics returned' })
  async getMetrics(@Query() query: MetricsQueryDto) {
    return this.dashboardService.getMetrics(query.period ?? '7d');
  }

  //__________ RECENT ACTIVITY ________________________
  @Get('activity')
  @ApiOperation({ summary: 'Recent chronological platform events' })
  @ApiResponse({ status: 200, description: 'Activity feed returned' })
  async getActivity(@Query() query: ActivityQueryDto) {
    return this.dashboardService.getActivity(query.limit ?? 6);
  }

  //__________ JOBS SUMMARY ________________________
  @Get('jobs-summary')
  @ApiOperation({ summary: 'Overall job status metrics' })
  @ApiResponse({ status: 200, description: 'Job summary returned' })
  async getJobsSummary() {
    return this.dashboardService.getJobsSummary();
  }

  //__________ HEALTH ________________________
  @Get('health')
  @ApiOperation({ summary: 'Real-time service checks & target progress' })
  @ApiResponse({ status: 200, description: 'Health metrics returned' })
  async getHealth() {
    return this.dashboardService.getHealth();
  }
}
