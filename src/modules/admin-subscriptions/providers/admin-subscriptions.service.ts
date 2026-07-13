import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { PlanInterval, Prisma } from '@prisma/client';
import {
  AssignPlanDto,
  CancelSubscriptionDto,
  ChangePlanDto,
  CreatePlanDto,
  ExtendSubscriptionDto,
  ListSubscriptionsQueryDto,
  UpdatePlanDto,
  WaivePaymentDto,
} from '../dto/admin-subscriptions.dto';

@Injectable()
export class AdminSubscriptionsService {
  constructor(private prisma: PrismaService) {}

  private userSelect = { select: { id: true, fullName: true, email: true } };

  private addInterval(from: Date, interval: PlanInterval): Date {
    const d = new Date(from);
    if (interval === 'YEARLY') d.setFullYear(d.getFullYear() + 1);
    else if (interval === 'QUARTERLY') d.setMonth(d.getMonth() + 3);
    else d.setMonth(d.getMonth() + 1);
    return d;
  }

  // ================= 12.1 plans =================
  public async listPlans() {
    return this.prisma.subscriptionPlan.findMany({
      include: { _count: { select: { subscriptions: true } } },
      orderBy: { price: 'asc' },
    });
  }

  public async getPlan(planId: string) {
    const plan = await this.prisma.subscriptionPlan.findUnique({
      where: { id: planId },
      include: { _count: { select: { subscriptions: true } } },
    });
    if (!plan) throw new NotFoundException('Plan not found');
    return plan;
  }

  public async plansSummary() {
    const [totalPlans, activePlans, archivedPlans, subscribers, revenueAgg] = await Promise.all([
      this.prisma.subscriptionPlan.count(),
      this.prisma.subscriptionPlan.count({ where: { archived: false } }),
      this.prisma.subscriptionPlan.count({ where: { archived: true } }),
      this.prisma.subscription.count({ where: { status: 'ACTIVE' } }),
      this.prisma.subscription.findMany({
        where: { status: 'ACTIVE' },
        include: { plan: { select: { price: true } } },
      }),
    ]);
    const mrr = revenueAgg.reduce((sum, s) => sum + (s.plan?.price ?? 0), 0);
    return { totalPlans, activePlans, archivedPlans, activeSubscribers: subscribers, mrr };
  }

  public async createPlan(dto: CreatePlanDto) {
    return this.prisma.subscriptionPlan.create({
      data: {
        name: dto.name,
        description: dto.description,
        price: dto.price,
        interval: (dto.interval ?? 'MONTHLY') as PlanInterval,
        features: dto.features ?? [],
        jobLimit: dto.jobLimit,
      },
    });
  }

  public async updatePlan(planId: string, dto: UpdatePlanDto) {
    await this.getPlan(planId);
    return this.prisma.subscriptionPlan.update({
      where: { id: planId },
      data: {
        ...(dto.name !== undefined && { name: dto.name }),
        ...(dto.description !== undefined && { description: dto.description }),
        ...(dto.price !== undefined && { price: dto.price }),
        ...(dto.interval !== undefined && { interval: dto.interval as PlanInterval }),
        ...(dto.features !== undefined && { features: dto.features }),
        ...(dto.jobLimit !== undefined && { jobLimit: dto.jobLimit }),
      },
    });
  }

  public async archivePlan(planId: string) {
    await this.getPlan(planId);
    await this.prisma.subscriptionPlan.update({
      where: { id: planId },
      data: { archived: true },
    });
    return { message: 'Plan archived; no new signups allowed' };
  }

  public async duplicatePlan(planId: string) {
    const plan = await this.getPlan(planId);
    return this.prisma.subscriptionPlan.create({
      data: {
        name: `${plan.name} (Copy)`,
        description: plan.description,
        price: plan.price,
        interval: plan.interval,
        features: plan.features,
        jobLimit: plan.jobLimit,
      },
    });
  }

  // ================= 12.2 subscribers =================
  public async listSubscriptions(query: ListSubscriptionsQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const skip = (page - 1) * limit;

    const where: Prisma.SubscriptionWhereInput = {};
    if (query.status) where.status = query.status as any;
    if (query.planId) where.planId = query.planId;
    if (query.search) {
      where.user = {
        OR: [
          { fullName: { contains: query.search, mode: 'insensitive' } },
          { email: { contains: query.search, mode: 'insensitive' } },
        ],
      };
    }

    const [items, total] = await Promise.all([
      this.prisma.subscription.findMany({
        where,
        include: { user: this.userSelect, plan: true },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.subscription.count({ where }),
    ]);
    return { items, total };
  }

  public async subscriptionsSummary() {
    const now = new Date();
    const soon = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const [active, cancelled, expired, expiringSoon] = await Promise.all([
      this.prisma.subscription.count({ where: { status: 'ACTIVE' } }),
      this.prisma.subscription.count({ where: { status: 'CANCELLED' } }),
      this.prisma.subscription.count({ where: { status: 'EXPIRED' } }),
      this.prisma.subscription.count({
        where: { status: 'ACTIVE', expiresAt: { gte: now, lte: soon } },
      }),
    ]);
    const totalEnded = cancelled + expired;
    const churnRate =
      active + totalEnded > 0
        ? Number(((totalEnded / (active + totalEnded)) * 100).toFixed(2))
        : 0;
    return { active, cancelled, expired, expiringSoon, churnRate };
  }

  private async findSubOrThrow(subId: string) {
    const sub = await this.prisma.subscription.findUnique({
      where: { id: subId },
      include: { user: this.userSelect, plan: true, notes: { orderBy: { createdAt: 'desc' } } },
    });
    if (!sub) throw new NotFoundException('Subscription not found');
    return sub;
  }

  public async getSubscription(subId: string) {
    return this.findSubOrThrow(subId);
  }

  public async changePlan(subId: string, dto: ChangePlanDto) {
    const sub = await this.findSubOrThrow(subId);
    const plan = await this.prisma.subscriptionPlan.findUnique({ where: { id: dto.planId } });
    if (!plan) throw new NotFoundException('Target plan not found');
    if (sub.planId === dto.planId) {
      return { message: 'Subscription already on this plan', idempotent: true };
    }
    await this.prisma.subscription.update({
      where: { id: subId },
      data: {
        planId: dto.planId,
        expiresAt: this.addInterval(new Date(), plan.interval),
      },
    });
    return { message: 'Subscription plan changed' };
  }

  public async cancel(subId: string, dto: CancelSubscriptionDto) {
    const sub = await this.findSubOrThrow(subId);
    if (sub.status === 'CANCELLED') {
      throw new BadRequestException('Subscription already cancelled');
    }
    const immediate = dto.mode === 'immediate';
    await this.prisma.subscription.update({
      where: { id: subId },
      data: {
        status: immediate ? 'CANCELLED' : sub.status,
        cancelledAt: new Date(),
        ...(immediate && { expiresAt: new Date() }),
      },
    });
    if (dto.reason) {
      await this.prisma.subscriptionNote.create({
        data: { subscriptionId: subId, content: `Cancellation reason: ${dto.reason}` },
      });
    }
    return {
      message: immediate
        ? 'Subscription cancelled immediately'
        : 'Subscription set to cancel at end of period',
    };
  }

  public async extend(subId: string, dto: ExtendSubscriptionDto) {
    const sub = await this.findSubOrThrow(subId);
    const base = sub.expiresAt && sub.expiresAt > new Date() ? sub.expiresAt : new Date();
    const expiresAt = new Date(base.getTime() + dto.days * 24 * 60 * 60 * 1000);
    await this.prisma.subscription.update({
      where: { id: subId },
      data: { expiresAt, status: 'ACTIVE' },
    });
    return { message: `Subscription extended by ${dto.days} days`, expiresAt };
  }

  public async waive(subId: string, dto: WaivePaymentDto) {
    await this.findSubOrThrow(subId);
    await this.prisma.subscriptionNote.create({
      data: { subscriptionId: subId, content: `Renewal fee waived: ${dto.reason}` },
    });
    return { message: 'Renewal fee waived' };
  }

  public async addNote(subId: string, content: string, authorId?: string) {
    await this.findSubOrThrow(subId);
    return this.prisma.subscriptionNote.create({
      data: { subscriptionId: subId, content, authorId: authorId ?? null },
    });
  }

  // ================= user-scoped =================
  public async getUserSubscription(userId: string) {
    const sub = await this.prisma.subscription.findFirst({
      where: { userId },
      include: { plan: true },
      orderBy: { createdAt: 'desc' },
    });
    if (!sub) return { userId, subscription: null };
    return {
      userId,
      subscription: sub,
      isActive: sub.status === 'ACTIVE',
    };
  }

  public async assignPlan(userId: string, dto: AssignPlanDto) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    const plan = await this.prisma.subscriptionPlan.findUnique({ where: { id: dto.planId } });
    if (!plan) throw new NotFoundException('Plan not found');

    const expiresAt = dto.durationDays
      ? new Date(Date.now() + dto.durationDays * 24 * 60 * 60 * 1000)
      : this.addInterval(new Date(), plan.interval);

    // Deactivate existing active subscriptions before force-assigning.
    await this.prisma.subscription.updateMany({
      where: { userId, status: 'ACTIVE' },
      data: { status: 'CANCELLED', cancelledAt: new Date() },
    });

    const sub = await this.prisma.subscription.create({
      data: { userId, planId: dto.planId, status: 'ACTIVE', expiresAt },
    });
    return { message: 'Plan assigned to user', subscriptionId: sub.id, expiresAt };
  }
}
