import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
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
import { AdminAppealsService } from './providers/admin-appeals.service';
import {
  AppealDecisionDto,
  EscalateAppealDto,
  ListAppealsQueryDto,
} from './dto/admin-appeals.dto';

@ApiTags('Admin Appeals')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/appeals')
export class AdminAppealsController {
  constructor(private readonly service: AdminAppealsService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated list of appeals' })
  list(@Query() query: ListAppealsQueryDto) {
    return this.service.list(query);
  }

  @Get('metrics')
  @ApiOperation({ summary: 'Appeals overall summary metrics' })
  metrics() {
    return this.service.metrics();
  }

  @Post(':id/decision')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Approve/deny appeal and release restrictions' })
  @ApiParam({ name: 'id', type: 'string' })
  decision(@Param('id', ParseUUIDPipe) id: string, @Body() dto: AppealDecisionDto) {
    return this.service.decision(id, dto);
  }

  @Post(':id/escalate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Escalate complex appeal to senior admin' })
  @ApiParam({ name: 'id', type: 'string' })
  escalate(@Param('id', ParseUUIDPipe) id: string, @Body() dto: EscalateAppealDto) {
    return this.service.escalate(id, dto);
  }
}
