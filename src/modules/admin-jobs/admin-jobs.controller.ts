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
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminJobsService } from './providers/admin-jobs.service';
import {
  ListJobsQueryDto,
  NoteContentDto,
  ReasonDto,
  ResolveDisputeDto,
} from './dto/admin-jobs.dto';

@ApiTags('Admin Jobs')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/jobs')
export class AdminJobsController {
  constructor(private readonly service: AdminJobsService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated job list with status & search' })
  list(@Query() query: ListJobsQueryDto) {
    return this.service.list(query);
  }

  @Get(':jobId')
  @ApiOperation({ summary: 'Fetch full job details, payment, milestones, timeline' })
  @ApiParam({ name: 'jobId', type: 'string' })
  getById(@Param('jobId', ParseUUIDPipe) jobId: string) {
    return this.service.getById(jobId);
  }

  @Post(':jobId/complete')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Force complete active job' })
  @ApiParam({ name: 'jobId', type: 'string' })
  complete(@Param('jobId', ParseUUIDPipe) jobId: string) {
    return this.service.complete(jobId);
  }

  @Post(':jobId/cancel')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Force cancel active job' })
  @ApiParam({ name: 'jobId', type: 'string' })
  cancel(@Param('jobId', ParseUUIDPipe) jobId: string, @Body() dto: ReasonDto) {
    return this.service.cancel(jobId, dto.reason);
  }

  @Post(':jobId/release-payment')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Manually release escrow funds to artisan' })
  @ApiParam({ name: 'jobId', type: 'string' })
  releasePayment(@Param('jobId', ParseUUIDPipe) jobId: string) {
    return this.service.releasePayment(jobId);
  }

  @Post(':jobId/refund')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refund escrow payment to client' })
  @ApiParam({ name: 'jobId', type: 'string' })
  refund(@Param('jobId', ParseUUIDPipe) jobId: string, @Body() dto: ReasonDto) {
    return this.service.refund(jobId, dto.reason);
  }

  @Post(':jobId/dispute')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Freeze job and open dispute' })
  @ApiParam({ name: 'jobId', type: 'string' })
  openDispute(@Param('jobId', ParseUUIDPipe) jobId: string, @Body() dto: ReasonDto) {
    return this.service.openDispute(jobId, dto.reason);
  }

  @Post(':jobId/dispute/resolve')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resolve dispute with financial outcome' })
  @ApiParam({ name: 'jobId', type: 'string' })
  resolveDispute(
    @Param('jobId', ParseUUIDPipe) jobId: string,
    @Body() dto: ResolveDisputeDto,
  ) {
    return this.service.resolveDispute(jobId, dto);
  }

  @Post(':jobId/dispute/note')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Add internal admin note to dispute' })
  @ApiParam({ name: 'jobId', type: 'string' })
  addDisputeNote(
    @Param('jobId', ParseUUIDPipe) jobId: string,
    @Body() dto: NoteContentDto,
    @Req() req: any,
  ) {
    return this.service.addDisputeNote(jobId, dto.content, req.user?.id);
  }
}
