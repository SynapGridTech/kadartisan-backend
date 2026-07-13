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
import { AdminComplaintsService } from './providers/admin-complaints.service';
import {
  AddDisputeEvidenceDto,
  CloseInvalidDto,
  ComplaintNoteDto,
  ListComplaintsQueryDto,
  ResolveComplaintDto,
  ResolveDisputePayloadDto,
} from './dto/admin-complaints.dto';

@ApiTags('Admin Complaints')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/complaints')
export class AdminComplaintsController {
  constructor(private readonly service: AdminComplaintsService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated complaints list' })
  list(@Query() query: ListComplaintsQueryDto) {
    return this.service.list(query);
  }

  @Get('summary')
  @ApiOperation({ summary: 'General complaint counts metrics' })
  summary() {
    return this.service.summary();
  }

  @Get(':complaintId')
  @ApiOperation({ summary: 'Fetch single complaint dossier' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  getById(@Param('complaintId', ParseUUIDPipe) complaintId: string) {
    return this.service.getById(complaintId);
  }

  @Post(':complaintId/start-review')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Transition status to 'In Review'" })
  @ApiParam({ name: 'complaintId', type: 'string' })
  startReview(@Param('complaintId', ParseUUIDPipe) complaintId: string) {
    return this.service.startReview(complaintId);
  }

  @Post(':complaintId/escalate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Flag status as 'Escalated'" })
  @ApiParam({ name: 'complaintId', type: 'string' })
  escalate(@Param('complaintId', ParseUUIDPipe) complaintId: string) {
    return this.service.escalate(complaintId);
  }

  @Post(':complaintId/deescalate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Remove 'Escalated' status" })
  @ApiParam({ name: 'complaintId', type: 'string' })
  deescalate(@Param('complaintId', ParseUUIDPipe) complaintId: string) {
    return this.service.deescalate(complaintId);
  }

  @Post(':complaintId/resolve')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Mark complaint resolved' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  resolve(
    @Param('complaintId', ParseUUIDPipe) complaintId: string,
    @Body() dto: ResolveComplaintDto,
  ) {
    return this.service.resolve(complaintId, dto);
  }

  @Post(':complaintId/close-invalid')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Dismiss complaint as invalid' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  closeInvalid(
    @Param('complaintId', ParseUUIDPipe) complaintId: string,
    @Body() dto: CloseInvalidDto,
  ) {
    return this.service.closeInvalid(complaintId, dto);
  }

  @Post(':complaintId/notes')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Add admin note to complaint record' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  addNote(
    @Param('complaintId', ParseUUIDPipe) complaintId: string,
    @Body() dto: ComplaintNoteDto,
    @Req() req: any,
  ) {
    return this.service.addNote(complaintId, dto.content, req.user?.id);
  }

  // ---------- 8.2 dispute sub-resource (nested under complaint) ----------
  @Get(':complaintId/dispute')
  @ApiOperation({ summary: 'Fetch dispute specifics & timelines' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  getDispute(@Param('complaintId', ParseUUIDPipe) complaintId: string) {
    return this.service.getDispute(complaintId);
  }

  @Post(':complaintId/dispute/resolve')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resolve dispute & trigger payouts/refunds' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  resolveDispute(
    @Param('complaintId', ParseUUIDPipe) complaintId: string,
    @Body() dto: ResolveDisputePayloadDto,
  ) {
    return this.service.resolveDispute(complaintId, dto);
  }

  @Post(':complaintId/dispute/evidence')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Log platform administrative evidence' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  addEvidence(
    @Param('complaintId', ParseUUIDPipe) complaintId: string,
    @Body() dto: AddDisputeEvidenceDto,
  ) {
    return this.service.addEvidence(complaintId, dto);
  }

  @Post(':complaintId/dispute/notes')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Append internal dispute note' })
  @ApiParam({ name: 'complaintId', type: 'string' })
  addDisputeNote(
    @Param('complaintId', ParseUUIDPipe) complaintId: string,
    @Body() dto: ComplaintNoteDto,
    @Req() req: any,
  ) {
    return this.service.addDisputeNote(complaintId, dto.content, req.user?.id);
  }
}

// ---------- 8.2 disputes summary (separate prefix) ----------
@ApiTags('Admin Complaints')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/disputes')
export class AdminDisputesController {
  constructor(private readonly service: AdminComplaintsService) {}

  @Get('summary')
  @ApiOperation({ summary: 'Overview counts for frozen escrows' })
  summary() {
    return this.service.disputesSummary();
  }
}
