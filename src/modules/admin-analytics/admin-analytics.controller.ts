import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminAnalyticsService } from './providers/admin-analytics.service';
import { AnalyticsQueryDto } from './dto/analytics-query.dto';

@ApiTags('Admin Analytics')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/analytics')
export class AdminAnalyticsController {
  constructor(private readonly analyticsService: AdminAnalyticsService) {}

  //__________ OVERVIEW ________________________
  @Get('overview')
  @ApiOperation({ summary: 'Platform-wide KPI overview, growth rates & funnel' })
  @ApiResponse({ status: 200, description: 'Overview data returned' })
  async getOverview(@Query() query: AnalyticsQueryDto) {
    return this.analyticsService.getOverview(query.period ?? '30d', query.compare === 'true');
  }

  //__________ USERS ________________________
  @Get('users')
  @ApiOperation({ summary: 'Registrations, verification rates & geo distribution' })
  @ApiResponse({ status: 200, description: 'Users analytics returned' })
  async getUsers(@Query() query: AnalyticsQueryDto) {
    return this.analyticsService.getUsers(query.period ?? '30d');
  }

  //__________ JOBS ________________________
  @Get('jobs')
  @ApiOperation({ summary: 'Job volumes, completion rates & category breakdowns' })
  @ApiResponse({ status: 200, description: 'Jobs analytics returned' })
  async getJobs(@Query() query: AnalyticsQueryDto) {
    return this.analyticsService.getJobs(query.period ?? '30d');
  }

  //__________ REVENUE ________________________
  @Get('revenue')
  @ApiOperation({ summary: 'Gross revenue, platform fees & gateway performance' })
  @ApiResponse({ status: 200, description: 'Revenue analytics returned' })
  async getRevenue(@Query() query: AnalyticsQueryDto) {
    return this.analyticsService.getRevenue(query.period ?? '30d');
  }

  //__________ ARTISAN PERFORMANCE ________________________
  @Get('artisan-performance')
  @ApiOperation({ summary: 'Ratings distribution & top/underperforming artisans' })
  @ApiResponse({ status: 200, description: 'Artisan performance returned' })
  async getArtisanPerformance(@Query() query: AnalyticsQueryDto) {
    return this.analyticsService.getArtisanPerformance(query.period ?? '30d');
  }
}
