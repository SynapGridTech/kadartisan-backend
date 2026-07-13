import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
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
import { AdminCommunicationsService } from './providers/admin-communications.service';
import {
  BroadcastDto,
  CreateTemplateDto,
  EstimateQueryDto,
  MessageLogQueryDto,
  TemplatesQueryDto,
  UpdateTemplateDto,
} from './dto/admin-communications.dto';

@ApiTags('Admin Communications')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/communications')
export class AdminCommunicationsController {
  constructor(private readonly service: AdminCommunicationsService) {}

  // ---------- broadcasts ----------
  @Post('broadcast')
  @ApiOperation({ summary: 'Disseminate message to defined channels' })
  broadcast(@Body() dto: BroadcastDto) {
    return this.service.broadcast(dto);
  }

  @Post('broadcast/test')
  @ApiOperation({ summary: 'Dispatch test message to active admin' })
  broadcastTest(@Body() dto: BroadcastDto) {
    return this.service.broadcastTest(dto);
  }

  @Get('broadcast/estimate')
  @ApiOperation({ summary: 'Compute potential audience size' })
  estimate(@Query() query: EstimateQueryDto) {
    return this.service.estimate(query.channels, query.audience);
  }

  // ---------- templates ----------
  @Get('templates')
  @ApiOperation({ summary: 'Fetch templates (system vs custom)' })
  listTemplates(@Query() query: TemplatesQueryDto) {
    return this.service.listTemplates(query);
  }

  @Get('templates/:id')
  @ApiOperation({ summary: 'Fetch single template content' })
  @ApiParam({ name: 'id', type: 'string' })
  getTemplate(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getTemplate(id);
  }

  @Post('templates')
  @ApiOperation({ summary: 'Create a new reusable template' })
  createTemplate(@Body() dto: CreateTemplateDto) {
    return this.service.createTemplate(dto);
  }

  @Put('templates/:id')
  @ApiOperation({ summary: 'Edit template configuration' })
  @ApiParam({ name: 'id', type: 'string' })
  updateTemplate(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateTemplateDto) {
    return this.service.updateTemplate(id, dto);
  }

  @Delete('templates/:id')
  @ApiOperation({ summary: 'Delete a template' })
  @ApiParam({ name: 'id', type: 'string' })
  deleteTemplate(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.deleteTemplate(id);
  }

  // ---------- message log ----------
  @Get('log')
  @ApiOperation({ summary: 'Paginated message logs' })
  log(@Query() query: MessageLogQueryDto) {
    return this.service.log(query);
  }

  @Get('summary')
  @ApiOperation({ summary: 'Log global counts and failure ratios' })
  summary() {
    return this.service.summary();
  }

  @Get('log/:messageId')
  @ApiOperation({ summary: 'Fetch message delivery status' })
  @ApiParam({ name: 'messageId', type: 'string' })
  getMessage(@Param('messageId', ParseUUIDPipe) messageId: string) {
    return this.service.getMessage(messageId);
  }
}
