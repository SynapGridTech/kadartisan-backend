import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import {
  AddFirewallIpDto,
  AuditLogQueryDto,
  AuthenticationSettingsDto,
  DataProtectionDto,
  FirewallSettingsDto,
  InviteAdminDto,
  UpdateAdminDto,
} from '../dto/admin-security.dto';

@Injectable()
export class AdminSecurityService {
  constructor(private prisma: PrismaService) {}

  private async getSetting<T>(key: string, fallback: T): Promise<T> {
    const row = await this.prisma.setting.findUnique({ where: { key } });
    return row ? (row.value as T) : fallback;
  }

  private async setSetting<T>(key: string, value: T): Promise<T> {
    await this.prisma.setting.upsert({
      where: { key },
      create: { key, value: value as any },
      update: { value: value as any },
    });
    return value;
  }

  // ================= authentication =================
  public async getAuthentication() {
    return this.getSetting('security.authentication', {
      twoFactorEnabled: false,
      loginAlertsEnabled: true,
      passwordPolicy: 'strong',
    });
  }

  public async updateAuthentication(dto: AuthenticationSettingsDto) {
    const settings = await this.setSetting('security.authentication', dto);
    return { settings };
  }

  // ================= admins =================
  public async listAdmins() {
    return this.prisma.user.findMany({
      where: { role: 'ADMIN' },
      select: {
        id: true,
        fullName: true,
        email: true,
        role: true,
        suspendedUntil: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async inviteAdmin(dto: InviteAdminDto) {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) throw new BadRequestException('A user with this email already exists');

    // Temporary random password; invited admin resets via forgot-password flow.
    const tempPassword = crypto.randomBytes(12).toString('hex');
    const hashed = await bcrypt.hash(tempPassword, 10);

    const admin = await this.prisma.user.create({
      data: {
        fullName: dto.name,
        email: dto.email,
        phoneNumber: `invite-${crypto.randomBytes(6).toString('hex')}`,
        password: hashed,
        role: 'ADMIN',
        isVerified: true,
        adminProfile: { create: {} },
      },
      select: { id: true, fullName: true, email: true, role: true },
    });
    await this.audit(null, 'admin.invite', 'User', admin.id);
    return { admin };
  }

  public async updateAdmin(id: string, dto: UpdateAdminDto) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user || user.role !== 'ADMIN') throw new NotFoundException('Admin not found');

    const data: Prisma.UserUpdateInput = {};
    if (dto.status === 'suspended') {
      data.suspendedUntil = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
      data.refreshToken = null;
    } else if (dto.status === 'active') {
      data.suspendedUntil = null;
    }

    const admin = await this.prisma.user.update({
      where: { id },
      data,
      select: { id: true, fullName: true, email: true, role: true, suspendedUntil: true },
    });
    return { admin };
  }

  public async removeAdmin(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user || user.role !== 'ADMIN') throw new NotFoundException('Admin not found');

    const adminCount = await this.prisma.user.count({ where: { role: 'ADMIN' } });
    if (adminCount <= 1) {
      throw new BadRequestException('Cannot remove the last remaining admin');
    }
    await this.prisma.user.delete({ where: { id } });
    await this.audit(null, 'admin.remove', 'User', id);
    return { message: 'Administrator account revoked' };
  }

  // ================= sessions =================
  public async listSessions() {
    return this.prisma.adminSession.findMany({
      select: { id: true, device: true, ip: true, lastActive: true },
      orderBy: { lastActive: 'desc' },
    });
  }

  public async revokeSession(id: string) {
    const session = await this.prisma.adminSession.findUnique({ where: { id } });
    if (!session) throw new NotFoundException('Session not found');
    await this.prisma.adminSession.delete({ where: { id } });
    return { message: 'Session revoked' };
  }

  public async revokeAllSessions(callerId?: string) {
    await this.prisma.adminSession.deleteMany({
      where: callerId ? { adminId: { not: callerId } } : {},
    });
    return { message: 'All other sessions revoked' };
  }

  // ================= firewall =================
  public async getFirewall() {
    const config = await this.getSetting('security.firewall', {
      ipWhitelistEnabled: false,
      rateLimitEnabled: true,
    });
    const whitelistedIPs = await this.prisma.firewallIp.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return { ...(config as object), whitelistedIPs };
  }

  public async updateFirewall(dto: FirewallSettingsDto) {
    const settings = await this.setSetting('security.firewall', dto);
    return { settings };
  }

  public async addFirewallIp(dto: AddFirewallIpDto) {
    const existing = await this.prisma.firewallIp.findUnique({ where: { ip: dto.ip } });
    if (existing) throw new BadRequestException('IP already whitelisted');
    const ip = await this.prisma.firewallIp.create({
      data: { ip: dto.ip, label: dto.label },
    });
    return { ip };
  }

  public async removeFirewallIp(id: string) {
    const ip = await this.prisma.firewallIp.findUnique({ where: { id } });
    if (!ip) throw new NotFoundException('Whitelisted IP not found');
    await this.prisma.firewallIp.delete({ where: { id } });
    return { message: 'IP removed from whitelist' };
  }

  // ================= audit logs =================
  public async auditLogs(query: AuditLogQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 50;
    const skip = (page - 1) * limit;

    const where: Prisma.AuditLogWhereInput = {};
    if (query.from || query.to) {
      where.createdAt = {};
      if (query.from) (where.createdAt as any).gte = new Date(query.from);
      if (query.to) (where.createdAt as any).lte = new Date(query.to);
    }

    const [data, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.auditLog.count({ where }),
    ]);
    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  public async exportAuditLogs(format: 'csv' | 'pdf') {
    const logs = await this.prisma.auditLog.findMany({
      orderBy: { createdAt: 'desc' },
      take: 5000,
    });

    if (format === 'pdf') {
      // Minimal placeholder PDF content; a real generator would stream binary.
      const body = logs
        .map((l) => `${l.createdAt.toISOString()} ${l.action} ${l.entity ?? ''}`)
        .join('\n');
      return { contentType: 'application/pdf', filename: 'audit-logs.pdf', body };
    }

    const header = 'id,action,entity,entityId,actorId,createdAt';
    const rows = logs.map(
      (l) =>
        `${l.id},${l.action},${l.entity ?? ''},${l.entityId ?? ''},${l.actorId ?? ''},${l.createdAt.toISOString()}`,
    );
    return {
      contentType: 'text/csv',
      filename: 'audit-logs.csv',
      body: [header, ...rows].join('\n'),
    };
  }

  // ================= data protection =================
  public async getDataProtection() {
    return this.getSetting('security.data-protection', {
      encryptionEnabled: true,
      gdprEnabled: true,
      backupStorage: 'cloud',
    });
  }

  public async updateDataProtection(dto: DataProtectionDto) {
    const settings = await this.setSetting('security.data-protection', dto);
    return { settings };
  }

  private async audit(actorId: string | null, action: string, entity?: string, entityId?: string) {
    await this.prisma.auditLog.create({
      data: { actorId, action, entity, entityId },
    });
  }
}
