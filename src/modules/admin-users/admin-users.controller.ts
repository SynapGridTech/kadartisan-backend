import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminUsersService } from './providers/admin-users.service';
import {
  CreateNoteDto,
  FlagUserDto,
  MessageUserDto,
  RevokeVerificationDto,
  SoftDeleteUserDto,
  UserControlsDto,
} from './dto/admin-users.dto';

@ApiTags('Admin Users')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin/users')
export class AdminUsersController {
  constructor(private readonly service: AdminUsersService) {}

  // ---------- 4.2 sub-tabs ----------
  @Get(':id/activity')
  @ApiOperation({ summary: 'User chronological activity log' })
  @ApiParam({ name: 'id', type: 'string' })
  getActivity(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getActivity(id);
  }

  @Get(':id/bookings')
  @ApiOperation({ summary: 'Bookings associated with user' })
  @ApiParam({ name: 'id', type: 'string' })
  getBookings(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getBookings(id);
  }

  @Get(':id/reviews')
  @ApiOperation({ summary: 'Reviews given or received by user' })
  @ApiParam({ name: 'id', type: 'string' })
  getReviews(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getReviews(id);
  }

  @Get(':id/posts')
  @ApiOperation({ summary: 'User portfolio/social posts' })
  @ApiParam({ name: 'id', type: 'string' })
  getPosts(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getPosts(id);
  }

  @Get(':id/transactions')
  @ApiOperation({ summary: 'User wallet transaction log' })
  @ApiParam({ name: 'id', type: 'string' })
  getTransactions(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getTransactions(id);
  }

  @Get(':id/reports')
  @ApiOperation({ summary: 'Complaints/reports filed by or against user' })
  @ApiParam({ name: 'id', type: 'string' })
  getReports(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getReports(id);
  }

  // ---------- 4.2 notes ----------
  @Get(':id/notes')
  @ApiOperation({ summary: 'Internal admin notes on this user' })
  @ApiParam({ name: 'id', type: 'string' })
  getNotes(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getNotes(id);
  }

  @Post(':id/notes')
  @ApiOperation({ summary: 'Add an internal admin note' })
  @ApiParam({ name: 'id', type: 'string' })
  addNote(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: CreateNoteDto,
    @Req() req: any,
  ) {
    return this.service.addNote(id, dto.content, req.user?.id);
  }

  @Delete(':id/notes/:noteId')
  @ApiOperation({ summary: 'Delete an internal admin note' })
  @ApiParam({ name: 'id', type: 'string' })
  @ApiParam({ name: 'noteId', type: 'string' })
  deleteNote(
    @Param('id', ParseUUIDPipe) id: string,
    @Param('noteId', ParseUUIDPipe) noteId: string,
  ) {
    return this.service.deleteNote(id, noteId);
  }

  // ---------- 4.3 actions ----------
  @Delete(':id')
  @ApiOperation({ summary: 'Soft-delete a user account' })
  @ApiParam({ name: 'id', type: 'string' })
  @ApiResponse({ status: 400, description: 'Confirmation name mismatch' })
  softDelete(@Param('id', ParseUUIDPipe) id: string, @Body() dto: SoftDeleteUserDto) {
    return this.service.softDelete(id, dto.confirmName);
  }

  @Post(':id/message')
  @ApiOperation({ summary: 'Send an in-app message to a user' })
  @ApiParam({ name: 'id', type: 'string' })
  message(@Param('id', ParseUUIDPipe) id: string, @Body() dto: MessageUserDto) {
    return this.service.message(id, dto.content);
  }

  @Patch(':id/controls')
  @ApiOperation({ summary: 'Toggle profile visibility' })
  @ApiParam({ name: 'id', type: 'string' })
  controls(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UserControlsDto) {
    return this.service.setControls(id, dto.profileVisible);
  }

  @Patch(':id/flag')
  @ApiOperation({ summary: 'Flag or unflag a user for review' })
  @ApiParam({ name: 'id', type: 'string' })
  flag(@Param('id', ParseUUIDPipe) id: string, @Body() dto: FlagUserDto) {
    return this.service.flag(id, dto.flagged, dto.reason);
  }

  @Patch(':id/verification/revoke')
  @ApiOperation({ summary: 'Revoke a user verification' })
  @ApiParam({ name: 'id', type: 'string' })
  revokeVerification(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: RevokeVerificationDto,
  ) {
    return this.service.revokeVerification(id, dto.reason);
  }
}
