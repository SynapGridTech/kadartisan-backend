import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { ComplaintStatus, Prisma } from '@prisma/client';
import {
  AddDisputeEvidenceDto,
  CloseInvalidDto,
  ListComplaintsQueryDto,
  ResolveComplaintDto,
  ResolveDisputePayloadDto,
} from '../dto/admin-complaints.dto';

@Injectable()
export class AdminComplaintsService {
  constructor(private prisma: PrismaService) {}

  private readonly tabMap: Record<string, ComplaintStatus> = {
    new: 'NEW',
    in_review: 'IN_REVIEW',
    escalated: 'ESCALATED',
    resolved: 'RESOLVED',
    closed_invalid: 'CLOSED_INVALID',
  };

  private userSelect = {
    select: { id: true, fullName: true, email: true },
  };

  // ---------- 8.1 complaints ----------
  public async list(query: ListComplaintsQueryDto) {
    const limit = query.limit ?? 20;
    const where: Prisma.ComplaintWhereInput = {};

    if (query.tab && this.tabMap[query.tab]) where.status = this.tabMap[query.tab];
    if (query.filedBy) where.filedById = query.filedBy;
    if (query.search) {
      where.OR = [
        { subject: { contains: query.search, mode: 'insensitive' } },
        { description: { contains: query.search, mode: 'insensitive' } },
      ];
    }
    if (query.dateRange) {
      const days = parseInt(query.dateRange.replace(/\D/g, ''), 10);
      if (!isNaN(days)) {
        where.createdAt = { gte: new Date(Date.now() - days * 24 * 60 * 60 * 1000) };
      }
    }

    const rows = await this.prisma.complaint.findMany({
      where,
      include: { filedBy: this.userSelect, against: this.userSelect },
      orderBy: { createdAt: 'desc' },
      take: limit + 1,
      ...(query.cursor ? { cursor: { id: query.cursor }, skip: 1 } : {}),
    });

    const hasMore = rows.length > limit;
    const data = hasMore ? rows.slice(0, limit) : rows;
    const nextCursor = hasMore ? data[data.length - 1].id : null;
    const total = await this.prisma.complaint.count({ where });

    return { data, nextCursor, total };
  }

  public async summary() {
    const [total, newCount, inReview, escalated, resolved, closedInvalid] = await Promise.all([
      this.prisma.complaint.count(),
      this.prisma.complaint.count({ where: { status: 'NEW' } }),
      this.prisma.complaint.count({ where: { status: 'IN_REVIEW' } }),
      this.prisma.complaint.count({ where: { status: 'ESCALATED' } }),
      this.prisma.complaint.count({ where: { status: 'RESOLVED' } }),
      this.prisma.complaint.count({ where: { status: 'CLOSED_INVALID' } }),
    ]);
    return { total, new: newCount, inReview, escalated, resolved, closedInvalid };
  }

  private async findOrThrow(complaintId: string) {
    const complaint = await this.prisma.complaint.findUnique({
      where: { id: complaintId },
    });
    if (!complaint) throw new NotFoundException('Complaint not found');
    return complaint;
  }

  public async getById(complaintId: string) {
    const complaint = await this.prisma.complaint.findUnique({
      where: { id: complaintId },
      include: {
        filedBy: this.userSelect,
        against: this.userSelect,
        notes: { orderBy: { createdAt: 'desc' } },
        dispute: { include: { evidence: true, notes: { orderBy: { createdAt: 'desc' } } } },
      },
    });
    if (!complaint) throw new NotFoundException('Complaint not found');
    return complaint;
  }

  public async startReview(complaintId: string) {
    await this.findOrThrow(complaintId);
    await this.prisma.complaint.update({
      where: { id: complaintId },
      data: { status: 'IN_REVIEW' },
    });
    return { message: 'Complaint moved to In Review' };
  }

  public async escalate(complaintId: string) {
    await this.findOrThrow(complaintId);
    await this.prisma.complaint.update({
      where: { id: complaintId },
      data: { status: 'ESCALATED', escalated: true },
    });
    return { message: 'Complaint escalated' };
  }

  public async deescalate(complaintId: string) {
    const complaint = await this.findOrThrow(complaintId);
    if (!complaint.escalated) {
      throw new BadRequestException('Complaint is not escalated');
    }
    await this.prisma.complaint.update({
      where: { id: complaintId },
      data: { status: 'IN_REVIEW', escalated: false },
    });
    return { message: 'Complaint de-escalated' };
  }

  public async resolve(complaintId: string, dto: ResolveComplaintDto) {
    await this.findOrThrow(complaintId);
    await this.prisma.complaint.update({
      where: { id: complaintId },
      data: {
        status: 'RESOLVED',
        escalated: false,
        outcome: dto.outcome,
        resolutionNotes: dto.notes,
      },
    });
    return { message: 'Complaint resolved' };
  }

  public async closeInvalid(complaintId: string, dto: CloseInvalidDto) {
    await this.findOrThrow(complaintId);
    await this.prisma.complaint.update({
      where: { id: complaintId },
      data: { status: 'CLOSED_INVALID', closeReason: dto.reason },
    });
    return { message: 'Complaint closed as invalid' };
  }

  public async addNote(complaintId: string, content: string, authorId?: string) {
    await this.findOrThrow(complaintId);
    await this.prisma.complaintNote.create({
      data: { complaintId, content, authorId: authorId ?? null },
    });
    return { message: 'Note added to complaint' };
  }

  // ---------- 8.2 disputes ----------
  public async disputesSummary() {
    const [open, resolved, frozenAgg] = await Promise.all([
      this.prisma.dispute.count({ where: { status: 'OPEN' } }),
      this.prisma.dispute.count({ where: { status: 'RESOLVED' } }),
      this.prisma.dispute.aggregate({
        _sum: { frozenAmount: true },
        where: { status: 'OPEN' },
      }),
    ]);
    return {
      openDisputes: open,
      resolvedDisputes: resolved,
      totalFrozenAmount: frozenAgg._sum.frozenAmount ?? 0,
    };
  }

  private async findDisputeOrThrow(complaintId: string) {
    const dispute = await this.prisma.dispute.findUnique({
      where: { complaintId },
      include: { evidence: true, notes: { orderBy: { createdAt: 'desc' } } },
    });
    if (!dispute) throw new NotFoundException('Dispute not found for this complaint');
    return dispute;
  }

  public async getDispute(complaintId: string) {
    return this.findDisputeOrThrow(complaintId);
  }

  public async resolveDispute(complaintId: string, dto: ResolveDisputePayloadDto) {
    const dispute = await this.findDisputeOrThrow(complaintId);
    if (dispute.status === 'RESOLVED') {
      throw new BadRequestException('Dispute already resolved');
    }
    await this.prisma.$transaction([
      this.prisma.dispute.update({
        where: { id: dispute.id },
        data: { status: 'RESOLVED', outcome: dto.outcome, resolvedAt: new Date() },
      }),
      this.prisma.disputeNoteEntry.create({
        data: {
          disputeId: dispute.id,
          content: `Resolved (${dto.outcome}${dto.amount ? `, amount ${dto.amount}` : ''}). ${dto.notes}`,
        },
      }),
      this.prisma.complaint.update({
        where: { id: complaintId },
        data: { status: 'RESOLVED', outcome: dto.outcome, resolutionNotes: dto.notes },
      }),
    ]);
    return { message: 'Dispute resolved and payouts/refunds triggered' };
  }

  public async addEvidence(complaintId: string, dto: AddDisputeEvidenceDto) {
    const dispute = await this.findDisputeOrThrow(complaintId);
    await this.prisma.disputeEvidence.create({
      data: {
        disputeId: dispute.id,
        label: dto.label,
        url: dto.url ?? null,
        note: dto.note ?? null,
      },
    });
    return { message: 'Evidence logged' };
  }

  public async addDisputeNote(complaintId: string, content: string, authorId?: string) {
    const dispute = await this.findDisputeOrThrow(complaintId);
    await this.prisma.disputeNoteEntry.create({
      data: { disputeId: dispute.id, content, authorId: authorId ?? null },
    });
    return { message: 'Note appended to dispute' };
  }
}
