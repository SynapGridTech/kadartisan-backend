import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

type Period = '7d' | '30d' | '90d';

@Injectable()
export class AdminAnalyticsService {
  constructor(private prisma: PrismaService) {}

  private days(period: Period): number {
    return period === '90d' ? 90 : period === '30d' ? 30 : 7;
  }

  private start(period: Period): Date {
    return new Date(Date.now() - this.days(period) * 24 * 60 * 60 * 1000);
  }

  private growth(current: number, previous: number): number {
    if (previous === 0) return current > 0 ? 100 : 0;
    return Number((((current - previous) / previous) * 100).toFixed(2));
  }

  // ---------- overview ----------
  public async getOverview(period: Period = '30d', compare = false) {
    const start = this.start(period);
    const prevStart = new Date(start.getTime() - this.days(period) * 24 * 60 * 60 * 1000);

    const [
      totalUsers,
      newUsers,
      prevUsers,
      totalJobs,
      completedJobs,
      revenueAgg,
      prevRevenueAgg,
      feeAgg,
    ] = await Promise.all([
      this.prisma.user.count(),
      this.prisma.user.count({ where: { createdAt: { gte: start } } }),
      this.prisma.user.count({ where: { createdAt: { gte: prevStart, lt: start } } }),
      this.prisma.serviceRequest.count({ where: { createdAt: { gte: start } } }),
      this.prisma.serviceRequest.count({
        where: { jobStatus: 'COMPLETED', createdAt: { gte: start } },
      }),
      this.prisma.transaction.aggregate({
        _sum: { amount: true },
        where: { status: 'SUCCESS', type: 'PAYMENT', createdAt: { gte: start } },
      }),
      this.prisma.transaction.aggregate({
        _sum: { amount: true },
        where: {
          status: 'SUCCESS',
          type: 'PAYMENT',
          createdAt: { gte: prevStart, lt: start },
        },
      }),
      this.prisma.transaction.aggregate({
        _sum: { platformFee: true },
        where: { status: 'SUCCESS', createdAt: { gte: start } },
      }),
    ]);

    const revenue = revenueAgg._sum.amount ?? 0;
    const prevRevenue = prevRevenueAgg._sum.amount ?? 0;

    // acquisition funnel
    const [signups, artisansApplied, artisansApproved, firstJobs] = await Promise.all([
      this.prisma.user.count({ where: { createdAt: { gte: start } } }),
      this.prisma.artisanProfile.count({ where: { createdAt: { gte: start } } }),
      this.prisma.artisanProfile.count({
        where: { artisanStatus: { in: ['APPROVED', 'ACTIVE'] }, createdAt: { gte: start } },
      }),
      this.prisma.serviceRequest.count({ where: { createdAt: { gte: start } } }),
    ]);

    return {
      period,
      cards: {
        totalUsers,
        newUsers,
        totalJobs,
        completedJobs,
        revenue,
        platformFees: feeAgg._sum.platformFee ?? 0,
      },
      growth: compare
        ? {
            users: this.growth(newUsers, prevUsers),
            revenue: this.growth(revenue, prevRevenue),
          }
        : undefined,
      funnel: [
        { stage: 'Signups', value: signups },
        { stage: 'Artisans applied', value: artisansApplied },
        { stage: 'Artisans approved', value: artisansApproved },
        { stage: 'Jobs created', value: firstJobs },
      ],
    };
  }

  // ---------- users ----------
  public async getUsers(period: Period = '30d') {
    const start = this.start(period);

    const [registrations, verified, totalArtisans, byState] = await Promise.all([
      this.prisma.user.count({ where: { createdAt: { gte: start } } }),
      this.prisma.user.count({ where: { isVerified: true, createdAt: { gte: start } } }),
      this.prisma.artisanProfile.count(),
      this.prisma.artisanProfile.groupBy({
        by: ['state'],
        _count: { _all: true },
      }),
    ]);

    const verificationRate =
      registrations > 0 ? Number(((verified / registrations) * 100).toFixed(2)) : 0;

    return {
      period,
      registrations,
      verified,
      verificationRate,
      totalArtisans,
      geoDistribution: byState.map((g) => ({
        state: g.state,
        count: g._count._all,
      })),
    };
  }

  // ---------- jobs ----------
  public async getJobs(period: Period = '30d') {
    const start = this.start(period);

    const [total, completed, cancelled, byCategory] = await Promise.all([
      this.prisma.serviceRequest.count({ where: { createdAt: { gte: start } } }),
      this.prisma.serviceRequest.count({
        where: { jobStatus: 'COMPLETED', createdAt: { gte: start } },
      }),
      this.prisma.serviceRequest.count({
        where: { jobStatus: 'CANCELLED', createdAt: { gte: start } },
      }),
      this.prisma.serviceRequest.groupBy({
        by: ['category'],
        _count: { _all: true },
        where: { createdAt: { gte: start } },
      }),
    ]);

    const completionRate = total > 0 ? Number(((completed / total) * 100).toFixed(2)) : 0;

    return {
      period,
      total,
      completed,
      cancelled,
      completionRate,
      categoryBreakdown: byCategory.map((g) => ({
        category: g.category,
        count: g._count._all,
      })),
    };
  }

  // ---------- revenue ----------
  public async getRevenue(period: Period = '30d') {
    const start = this.start(period);

    const [grossAgg, feeAgg, txnTotal, txnSuccess, byGateway] = await Promise.all([
      this.prisma.transaction.aggregate({
        _sum: { amount: true },
        where: { status: 'SUCCESS', type: 'PAYMENT', createdAt: { gte: start } },
      }),
      this.prisma.transaction.aggregate({
        _sum: { platformFee: true },
        where: { status: 'SUCCESS', createdAt: { gte: start } },
      }),
      this.prisma.transaction.count({ where: { createdAt: { gte: start } } }),
      this.prisma.transaction.count({
        where: { status: 'SUCCESS', createdAt: { gte: start } },
      }),
      this.prisma.transaction.groupBy({
        by: ['gateway'],
        _sum: { amount: true },
        _count: { _all: true },
        where: { status: 'SUCCESS', createdAt: { gte: start } },
      }),
    ]);

    const txnSuccessRate = txnTotal > 0 ? Number(((txnSuccess / txnTotal) * 100).toFixed(2)) : 0;

    return {
      period,
      grossRevenue: grossAgg._sum.amount ?? 0,
      platformFees: feeAgg._sum.platformFee ?? 0,
      txnSuccessRate,
      gateways: byGateway.map((g) => ({
        gateway: g.gateway ?? 'unknown',
        volume: g._sum.amount ?? 0,
        count: g._count._all,
      })),
    };
  }

  // ---------- artisan performance ----------
  public async getArtisanPerformance(period: Period = '30d') {
    const [ratingBuckets, active, top, under] = await Promise.all([
      this.prisma.artisanProfile.groupBy({
        by: ['rating'],
        _count: { _all: true },
      }),
      this.prisma.artisanProfile.count({ where: { artisanStatus: 'ACTIVE' } }),
      this.prisma.artisanProfile.findMany({
        orderBy: [{ rating: 'desc' }, { completedJobs: 'desc' }],
        take: 5,
        select: {
          id: true,
          rating: true,
          completedJobs: true,
          user: { select: { fullName: true } },
        },
      }),
      this.prisma.artisanProfile.findMany({
        where: { artisanStatus: { in: ['APPROVED', 'ACTIVE'] } },
        orderBy: [{ rating: 'asc' }],
        take: 5,
        select: {
          id: true,
          rating: true,
          completedJobs: true,
          user: { select: { fullName: true } },
        },
      }),
    ]);

    const distribution = ratingBuckets.reduce<Record<string, number>>((acc, b) => {
      const bucket = Math.floor(b.rating).toString();
      acc[bucket] = (acc[bucket] ?? 0) + b._count._all;
      return acc;
    }, {});

    return {
      period,
      ratingsDistribution: distribution,
      activeArtisans: active,
      topArtisans: top.map((a) => ({
        id: a.id,
        name: a.user.fullName,
        rating: a.rating,
        completedJobs: a.completedJobs,
      })),
      underperformingArtisans: under.map((a) => ({
        id: a.id,
        name: a.user.fullName,
        rating: a.rating,
        completedJobs: a.completedJobs,
      })),
    };
  }
}
