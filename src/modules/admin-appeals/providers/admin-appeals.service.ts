import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { AppealType, Prisma } from '@prisma/client';
import {
  AppealDecisionDto,
  EscalateAppealDto,
  ListAppealsQueryDto,
} from '../dto/admin-appeals.dto';

@Injectable()
export class AdminAppealsService {
  constructor(private prisma: PrismaService) {}

  private readonly typeMap: Record<string, AppealType> = {
    suspension: 'SUSPENSION',
    verification: 'VERIFICATION',
    payout_hold: 'PAYOUT_HOLD',
  };

  private userSelect = {
    select: {
      id: true,
      fullName: true,
      email: true,
      suspendedUntil: true,
      bannedAt: true,
    },
  };

  public async list(query: ListAppealsQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 10;
    const skip = (page - 1) * limit;

    const where: Prisma.AppealWhereInput = {};
    if (query.tab === 'pending') where.status = 'PENDING';
    if (query.tab === 'in_review') where.status = 'IN_REVIEW';
    if (query.type) where.type = this.typeMap[query.type];
    if (query.urgent === 'true') where.urgent = true;
    if (query.search) {
      where.user = {
        OR: [
          { fullName: { contains: query.search, mode: 'insensitive' } },
          { email: { contains: query.search, mode: 'insensitive' } },
        ],
      };
    }

    const [items, total] = await Promise.all([
      this.prisma.appeal.findMany({
        where,
        include: { user: this.userSelect },
        orderBy: [{ urgent: 'desc' }, { createdAt: 'desc' }],
        skip,
        take: limit,
      }),
      this.prisma.appeal.count({ where }),
    ]);

    return { items, total };
  }

  public async metrics() {
    const [total, pending, inReview, approved, denied, escalated, urgent] = await Promise.all([
      this.prisma.appeal.count(),
      this.prisma.appeal.count({ where: { status: 'PENDING' } }),
      this.prisma.appeal.count({ where: { status: 'IN_REVIEW' } }),
      this.prisma.appeal.count({ where: { status: 'APPROVED' } }),
      this.prisma.appeal.count({ where: { status: { in: ['DENIED', 'REJECTED'] } } }),
      this.prisma.appeal.count({ where: { escalated: true } }),
      this.prisma.appeal.count({ where: { urgent: true } }),
    ]);
    return { total, pending, inReview, approved, denied, escalated, urgent };
  }

  private async findOrThrow(id: string) {
    const appeal = await this.prisma.appeal.findUnique({ where: { id } });
    if (!appeal) throw new NotFoundException('Appeal not found');
    return appeal;
  }

  public async decision(id: string, dto: AppealDecisionDto) {
    const appeal = await this.findOrThrow(id);
    if (['APPROVED', 'DENIED', 'REJECTED'].includes(appeal.status)) {
      throw new BadRequestException('Appeal has already been decided');
    }

    const status = dto.decision === 'approved' ? 'APPROVED' : 'DENIED';

    const ops: Prisma.PrismaPromise<any>[] = [
      this.prisma.appeal.update({
        where: { id },
        data: {
          status,
          responseText: dto.responseText,
          adminNote: dto.adminNote,
          decidedAt: new Date(),
        },
      }),
    ];

    // On approval, lift the restriction relevant to the appeal type.
    if (dto.decision === 'approved') {
      const data: Prisma.UserUpdateInput =
        appeal.type === 'VERIFICATION'
          ? { isVerified: true }
          : { suspendedUntil: null, suspensionReason: null, bannedAt: null, banReason: null };
      ops.push(this.prisma.user.update({ where: { id: appeal.userId }, data }));
    }

    await this.prisma.$transaction(ops);
    return { message: `Appeal ${dto.decision} successfully` };
  }

  public async escalate(id: string, dto: EscalateAppealDto) {
    await this.findOrThrow(id);
    await this.prisma.appeal.update({
      where: { id },
      data: { escalated: true, escalationNote: dto.note, status: 'IN_REVIEW' },
    });
    return { message: 'Appeal escalated to senior admin' };
  }
}
