import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { BadgeStatus, BadgeType, Prisma } from '@prisma/client';
import { ListBadgesQueryDto, ReviewBadgeDto } from '../dto/admin-badges.dto';

@Injectable()
export class AdminBadgesService {
  constructor(private prisma: PrismaService) {}

  private readonly statusMap: Record<string, BadgeStatus> = {
    pending: 'PENDING',
    active: 'ACTIVE',
    revoked: 'REVOKED',
  };

  private readonly typeMap: Record<string, BadgeType> = {
    verified: 'VERIFIED',
    top_artisan: 'TOP_ARTISAN',
  };

  public async list(query: ListBadgesQueryDto) {
    const where: Prisma.BadgeWhereInput = {};
    if (query.status) where.status = this.statusMap[query.status];
    if (query.type) where.type = this.typeMap[query.type];
    if (query.search) {
      where.user = { fullName: { contains: query.search, mode: 'insensitive' } };
    }

    return this.prisma.badge.findMany({
      where,
      include: { user: { select: { id: true, fullName: true, email: true } } },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async metrics() {
    const [total, pending, awarded, revoked] = await Promise.all([
      this.prisma.badge.count(),
      this.prisma.badge.count({ where: { status: 'PENDING' } }),
      this.prisma.badge.count({ where: { status: 'ACTIVE' } }),
      this.prisma.badge.count({ where: { status: 'REVOKED' } }),
    ]);
    return { total, pending, awarded, revoked };
  }

  public async review(badgeId: string, dto: ReviewBadgeDto) {
    const badge = await this.prisma.badge.findUnique({ where: { id: badgeId } });
    if (!badge) throw new NotFoundException('Badge request not found');

    const data: Prisma.BadgeUpdateInput = { note: dto.note };
    if (dto.decision === 'award') {
      data.status = 'ACTIVE';
      data.awardedAt = new Date();
      data.reason = null;
    } else if (dto.decision === 'reject') {
      data.status = 'REJECTED';
      data.reason = dto.reason ?? null;
    } else {
      data.status = 'HELD';
      data.reason = dto.reason ?? null;
    }

    return this.prisma.badge.update({ where: { id: badgeId }, data });
  }

  public async revoke(badgeId: string) {
    const badge = await this.prisma.badge.findUnique({ where: { id: badgeId } });
    if (!badge) throw new NotFoundException('Badge not found');

    await this.prisma.badge.update({
      where: { id: badgeId },
      data: { status: 'REVOKED', revokedAt: new Date() },
    });
    return { message: 'Badge revoked successfully' };
  }
}
