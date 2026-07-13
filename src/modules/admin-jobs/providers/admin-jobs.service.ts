import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { Prisma } from '@prisma/client';
import {
  ListJobsQueryDto,
  ResolveDisputeDto,
} from '../dto/admin-jobs.dto';

@Injectable()
export class AdminJobsService {
  constructor(private prisma: PrismaService) {}

  private readonly jobInclude = {
    customer: { include: { user: { select: { id: true, fullName: true, email: true } } } },
    acceptedArtisan: {
      include: { user: { select: { id: true, fullName: true, email: true } } },
    },
    milestones: { orderBy: { createdAt: 'asc' } },
    escrow: true,
    transactions: { orderBy: { createdAt: 'desc' } },
    disputeNotes: { orderBy: { createdAt: 'desc' } },
  } satisfies Prisma.ServiceRequestInclude;

  // ---------- list (cursor pagination) ----------
  public async list(query: ListJobsQueryDto) {
    const limit = query.limit ?? 20;
    const where: Prisma.ServiceRequestWhereInput = {};
    if (query.status) where.jobStatus = query.status as any;
    if (query.urgency) where.urgency = query.urgency;
    if (query.category) where.category = query.category;
    if (query.search) {
      where.OR = [
        { title: { contains: query.search, mode: 'insensitive' } },
        { description: { contains: query.search, mode: 'insensitive' } },
      ];
    }

    const rows = await this.prisma.serviceRequest.findMany({
      where,
      include: {
        customer: {
          include: { user: { select: { id: true, fullName: true, email: true } } },
        },
        acceptedArtisan: {
          include: { user: { select: { id: true, fullName: true } } },
        },
        escrow: true,
      },
      orderBy: { createdAt: 'desc' },
      take: limit + 1,
      ...(query.cursor ? { cursor: { id: query.cursor }, skip: 1 } : {}),
    });

    const hasMore = rows.length > limit;
    const data = hasMore ? rows.slice(0, limit) : rows;
    const nextCursor = hasMore ? data[data.length - 1].id : null;

    return { data, nextCursor };
  }

  public async getById(jobId: string) {
    const job = await this.prisma.serviceRequest.findUnique({
      where: { id: jobId },
      include: this.jobInclude,
    });
    if (!job) throw new NotFoundException('Job not found');
    return job;
  }

  private async findJobOrThrow(jobId: string) {
    const job = await this.prisma.serviceRequest.findUnique({
      where: { id: jobId },
      include: { escrow: true },
    });
    if (!job) throw new NotFoundException('Job not found');
    return job;
  }

  // ---------- lifecycle ----------
  public async complete(jobId: string) {
    const job = await this.findJobOrThrow(jobId);
    if (job.jobStatus === 'COMPLETED') {
      throw new BadRequestException('Job is already completed');
    }
    await this.prisma.serviceRequest.update({
      where: { id: jobId },
      data: { jobStatus: 'COMPLETED', status: 'COMPLETED' },
    });
    return { message: 'Job force-completed successfully' };
  }

  public async cancel(jobId: string, reason: string) {
    const job = await this.findJobOrThrow(jobId);
    if (job.jobStatus === 'CANCELLED') {
      throw new BadRequestException('Job is already cancelled');
    }
    await this.prisma.serviceRequest.update({
      where: { id: jobId },
      data: {
        jobStatus: 'CANCELLED',
        status: 'CANCELLED',
        disputeReason: reason,
      },
    });
    return { message: 'Job force-cancelled successfully' };
  }

  // ---------- escrow ----------
  public async releasePayment(jobId: string) {
    const job = await this.findJobOrThrow(jobId);
    if (!job.escrow) throw new BadRequestException('No escrow held for this job');
    if (job.escrow.status !== 'HELD') {
      throw new BadRequestException(`Escrow is already ${job.escrow.status.toLowerCase()}`);
    }
    await this.prisma.escrow.update({
      where: { jobId },
      data: { status: 'RELEASED' },
    });
    return { message: 'Escrow funds released to artisan' };
  }

  public async refund(jobId: string, reason: string) {
    const job = await this.findJobOrThrow(jobId);
    if (!job.escrow) throw new BadRequestException('No escrow held for this job');
    if (job.escrow.status !== 'HELD') {
      throw new BadRequestException(`Escrow is already ${job.escrow.status.toLowerCase()}`);
    }
    await this.prisma.escrow.update({
      where: { jobId },
      data: { status: 'REFUNDED' },
    });
    await this.prisma.serviceRequest.update({
      where: { id: jobId },
      data: { disputeReason: reason },
    });
    return { message: 'Escrow payment refunded to client' };
  }

  // ---------- disputes ----------
  public async openDispute(jobId: string, reason: string) {
    const job = await this.findJobOrThrow(jobId);
    if (job.disputeState === 'OPEN') {
      throw new BadRequestException('Job already has an open dispute');
    }
    await this.prisma.serviceRequest.update({
      where: { id: jobId },
      data: { disputeState: 'OPEN', disputeReason: reason },
    });
    return { message: 'Dispute opened and job frozen' };
  }

  public async resolveDispute(jobId: string, dto: ResolveDisputeDto) {
    const job = await this.findJobOrThrow(jobId);
    if (job.disputeState !== 'OPEN') {
      throw new BadRequestException('No open dispute to resolve');
    }

    const escrowStatus = dto.outcome === 'artisan' ? 'RELEASED' : 'REFUNDED';

    await this.prisma.$transaction([
      this.prisma.serviceRequest.update({
        where: { id: jobId },
        data: { disputeState: 'RESOLVED' },
      }),
      ...(job.escrow && job.escrow.status === 'HELD'
        ? [
            this.prisma.escrow.update({
              where: { jobId },
              data: { status: escrowStatus },
            }),
          ]
        : []),
      this.prisma.disputeNote.create({
        data: {
          jobId,
          content: `Dispute resolved in favor of ${dto.outcome}. ${dto.notes}`,
        },
      }),
    ]);

    return { message: `Dispute resolved in favor of ${dto.outcome}` };
  }

  public async addDisputeNote(jobId: string, content: string, authorId?: string) {
    await this.findJobOrThrow(jobId);
    await this.prisma.disputeNote.create({
      data: { jobId, content, authorId: authorId ?? null },
    });
    return { message: 'Note added to dispute' };
  }
}
