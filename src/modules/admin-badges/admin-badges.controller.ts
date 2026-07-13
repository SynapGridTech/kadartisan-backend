import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminBadgesService } from './providers/admin-badges.service';
import { ListBadgesQueryDto, ReviewBadgeDto } from './dto/admin-badges.dto';

@ApiTags('Admin Badges')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/badges')
export class AdminBadgesController {
  constructor(private readonly service: AdminBadgesService) {}

  @Get()
  @ApiOperation({ summary: 'List badge requests with filters' })
  list(@Query() query: ListBadgesQueryDto) {
    return this.service.list(query);
  }

  @Get('metrics')
  @ApiOperation({ summary: 'Badge status overview metrics' })
  metrics() {
    return this.service.metrics();
  }

  @Post(':badgeId/review')
  @ApiOperation({ summary: 'Approve, reject, or hold a badge request' })
  @ApiParam({ name: 'badgeId', type: 'string' })
  review(@Param('badgeId', ParseUUIDPipe) badgeId: string, @Body() dto: ReviewBadgeDto) {
    return this.service.review(badgeId, dto);
  }

  @Delete(':badgeId')
  @ApiOperation({ summary: 'Revoke a badge from an artisan' })
  @ApiParam({ name: 'badgeId', type: 'string' })
  revoke(@Param('badgeId', ParseUUIDPipe) badgeId: string) {
    return this.service.revoke(badgeId);
  }
}
