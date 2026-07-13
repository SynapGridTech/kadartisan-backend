import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { Prisma } from '@prisma/client';
import { InitiateRefundDto, ListTransactionsQueryDto } from '../dto/admin-transactions.dto';

@Injectable()
export class AdminTransactionsService {
  constructor(private prisma: PrismaService) {}

  // ---------- 6.1 monitoring ----------
  public async list(query: ListTransactionsQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const skip = (page - 1) * limit;

    const where: Prisma.TransactionWhereInput = {};
    if (query.status) where.status = query.status as any;
    if (query.type) where.type = query.type as any;
    if (query.search) {
      where.OR = [
        { reference: { contains: query.search, mode: 'insensitive' } },
        { description: { contains: query.search, mode: 'insensitive' } },
      ];
    }

    const [data, total] = await Promise.all([
      this.prisma.transaction.findMany({
        where,
        include: { user: { select: { id: true, fullName: true, email: true } } },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.transaction.count({ where }),
    ]);

    return {
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  // ---------- 6.2 refunds ----------
  public async initiateRefund(
    transactionId: string,
    idempotencyKey: string,
    dto: InitiateRefundDto,
  ) {
    if (!idempotencyKey) {
      throw new BadRequestException('X-Idempotency-Key header is required');
    }

    // Idempotency: return existing refund if key already used.
    const existing = await this.prisma.refund.findUnique({
      where: { idempotencyKey },
    });
    if (existing) {
      return {
        refundId: existing.id,
        status: existing.status,
        idempotent: true,
      };
    }

    const txn = await this.prisma.transaction.findUnique({
      where: { id: transactionId },
      include: { refunds: true },
    });
    if (!txn) throw new NotFoundException('Transaction not found');
    if (txn.status !== 'SUCCESS') {
      throw new BadRequestException('Only successful transactions can be refunded');
    }

    const alreadyRefunded = txn.refunds
      .filter((r) => r.status !== 'FAILED')
      .reduce((sum, r) => sum + r.amount, 0);
    const amount = dto.amount ?? txn.amount - alreadyRefunded;

    if (amount <= 0 || alreadyRefunded + amount > txn.amount) {
      throw new BadRequestException('Refund amount exceeds refundable balance');
    }

    const refund = await this.prisma.refund.create({
      data: {
        transactionId,
        amount,
        reason: dto.reason,
        status: 'PROCESSING',
        idempotencyKey,
      },
    });

    return {
      refundId: refund.id,
      transactionId,
      amount,
      status: refund.status,
      idempotent: false,
    };
  }

  public async getRefundMetadata(transactionId: string) {
    const txn = await this.prisma.transaction.findUnique({
      where: { id: transactionId },
      include: { refunds: { orderBy: { createdAt: 'desc' } } },
    });
    if (!txn) throw new NotFoundException('Transaction not found');

    const refundedTotal = txn.refunds
      .filter((r) => r.status === 'COMPLETED')
      .reduce((sum, r) => sum + r.amount, 0);

    return {
      transactionId: txn.id,
      reference: txn.reference,
      amount: txn.amount,
      refundedTotal,
      refundableBalance: txn.amount - refundedTotal,
      refunds: txn.refunds,
    };
  }

  public async getRefundStatus(refundId: string) {
    const refund = await this.prisma.refund.findUnique({ where: { id: refundId } });
    if (!refund) throw new NotFoundException('Refund not found');
    return { status: refund.status };
  }

  public async getRefundPolicy() {
    const setting = await this.prisma.setting.findUnique({
      where: { key: 'payment.refund-policy' },
    });
    if (setting) return setting.value;

    // Default policy derived from fee-structure if no explicit policy is stored.
    const fee = await this.prisma.setting.findUnique({
      where: { key: 'payment.fee-structure' },
    });
    return {
      commissionRate: (fee?.value as any)?.commissionRate ?? 10,
      commissionType: (fee?.value as any)?.commissionType ?? 'percentage',
      refundWindowDays: 14,
      guidelines:
        'Refunds are available within the refund window for eligible successful transactions.',
    };
  }
}
