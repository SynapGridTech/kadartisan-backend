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
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Response } from 'express';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminSecurityService } from './providers/admin-security.service';
import {
  AddFirewallIpDto,
  AuditLogQueryDto,
  AuthenticationSettingsDto,
  DataProtectionDto,
  FirewallSettingsDto,
  InviteAdminDto,
  UpdateAdminDto,
} from './dto/admin-security.dto';

@ApiTags('Admin Security')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('security')
export class AdminSecurityController {
  constructor(private readonly service: AdminSecurityService) {}

  // authentication
  @Get('authentication')
  @ApiOperation({ summary: 'Get 2FA, login alert policies' })
  getAuthentication() {
    return this.service.getAuthentication();
  }

  @Put('authentication')
  @ApiOperation({ summary: 'Update 2FA enforce criteria' })
  updateAuthentication(@Body() dto: AuthenticationSettingsDto) {
    return this.service.updateAuthentication(dto);
  }

  // admins
  @Get('admins')
  @ApiOperation({ summary: 'List active admin profiles' })
  listAdmins() {
    return this.service.listAdmins();
  }

  @Post('admins')
  @ApiOperation({ summary: 'Invite new system administrator' })
  inviteAdmin(@Body() dto: InviteAdminDto) {
    return this.service.inviteAdmin(dto);
  }

  @Put('admins/:id')
  @ApiOperation({ summary: 'Update roles or suspend administrator access' })
  @ApiParam({ name: 'id', type: 'string' })
  updateAdmin(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateAdminDto) {
    return this.service.updateAdmin(id, dto);
  }

  @Delete('admins/:id')
  @ApiOperation({ summary: 'Revoke/delete administrative user account' })
  @ApiParam({ name: 'id', type: 'string' })
  removeAdmin(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.removeAdmin(id);
  }

  // sessions
  @Get('sessions')
  @ApiOperation({ summary: 'Fetch active concurrent admin sessions' })
  listSessions() {
    return this.service.listSessions();
  }

  @Delete('sessions/:id')
  @ApiOperation({ summary: 'Revoke single active admin session' })
  @ApiParam({ name: 'id', type: 'string' })
  revokeSession(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.revokeSession(id);
  }

  @Delete('sessions')
  @ApiOperation({ summary: 'Revoke all sessions (except caller)' })
  revokeAllSessions(@Req() req: any) {
    return this.service.revokeAllSessions(req.user?.id);
  }

  // firewall
  @Get('firewall')
  @ApiOperation({ summary: 'Fetch IP whitelist rules and rate-limit status' })
  getFirewall() {
    return this.service.getFirewall();
  }

  @Put('firewall')
  @ApiOperation({ summary: 'Update rate-limiting switches' })
  updateFirewall(@Body() dto: FirewallSettingsDto) {
    return this.service.updateFirewall(dto);
  }

  @Post('firewall/ips')
  @ApiOperation({ summary: 'Append IP address to whitelist' })
  addFirewallIp(@Body() dto: AddFirewallIpDto) {
    return this.service.addFirewallIp(dto);
  }

  @Delete('firewall/ips/:id')
  @ApiOperation({ summary: 'Remove whitelisted IP address' })
  @ApiParam({ name: 'id', type: 'string' })
  removeFirewallIp(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.removeFirewallIp(id);
  }

  // audit logs
  @Get('audit-logs')
  @ApiOperation({ summary: 'Fetch system configuration audit trails' })
  auditLogs(@Query() query: AuditLogQueryDto) {
    return this.service.auditLogs(query);
  }

  @Get('audit-logs/export')
  @ApiOperation({ summary: 'Download audit CSV/PDF' })
  @ApiQuery({ name: 'format', enum: ['csv', 'pdf'], required: false })
  async exportAuditLogs(
    @Query('format') format: 'csv' | 'pdf' = 'csv',
    @Res() res: Response,
  ) {
    const result = await this.service.exportAuditLogs(format === 'pdf' ? 'pdf' : 'csv');
    res.setHeader('Content-Type', result.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
    res.send(result.body);
  }

  // data protection
  @Get('data-protection')
  @ApiOperation({ summary: 'Get active data encryption policies' })
  getDataProtection() {
    return this.service.getDataProtection();
  }

  @Put('data-protection')
  @ApiOperation({ summary: 'Update data protection configurations' })
  updateDataProtection(@Body() dto: DataProtectionDto) {
    return this.service.updateDataProtection(dto);
  }
}
