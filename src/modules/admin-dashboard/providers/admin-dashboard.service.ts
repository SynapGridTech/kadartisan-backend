import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

type Period = 'today' | '7d' | '30d';

@Injectable()
export class AdminDashboardService {
  constructor(private prisma: PrismaService) {}

  private periodStart(period: Period): Date {
    const now = new Date();
    if (period === 'today') {
      return new Date(now.getFullYear(), now.getMonth(), now.getDate());
    }
    const days = period === '30d' ? 30 : 7;
    return new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  }

  // ---------- 2.1 Attention & actions needed ----------
  public async getAttention() {
    const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [
      pendingVerifications,
      verificationsOver24h,
      openComplaints,
      escalatedComplaints,
      stuckTransactions,
      failedPayouts,
    ] = await Promise.all([
      this.prisma.artisanProfile.count({ where: { artisanStatus: 'PENDING' } }),
      this.prisma.artisanProfile.count({
        where: { artisanStatus: 'PENDING', createdAt: { lt: dayAgo } },
      }),
      this.prisma.complaint.count({
        where: { status: { in: ['NEW', 'IN_REVIEW'] } },
      }),
      this.prisma.complaint.count({ where: { status: 'ESCALATED' } }),
      this.prisma.transaction.count({ where: { status: 'STUCK' } }),
      this.prisma.transaction.count({
        where: { type: 'PAYOUT', status: 'FAILED' },
      }),
    ]);

    const quickActions = [
      {
        id: 'review-verifications',
        label: 'Review pending verifications',
        count: pendingVerifications,
        href: '/dashboard/verifications',
      },
      {
        id: 'handle-complaints',
        label: 'Handle open complaints',
        count: openComplaints,
        href: '/dashboard/complaints',
      },
      {
        id: 'resolve-stuck-transactions',
        label: 'Resolve stuck transactions',
        count: stuckTransactions,
        href: '/dashboard/transactions',
      },
    ];

    return {
      pendingVerifications,
      verificationsOver24h,
      openComplaints,
      escalatedComplaints,
      stuckTransactions,
      failedPayouts,
      quickActions,
    };
  }

  // ---------- 2.1 Platform KPIs ----------
  public async getMetrics(period: Period = '7d') {
    const start = this.periodStart(period);
    const prevStart = new Date(start.getTime() - (Date.now() - start.getTime()));

    const [
      totalUsers,
      prevTotalUsers,
      newArtisans,
      newCustomers,
      activeJobs,
      prevActiveJobs,
      revenueAgg,
      prevRevenueAgg,
      txnTotal,
      txnSuccess,
    ] = await Promise.all([
      this.prisma.user.count(),
      this.prisma.user.count({ where: { createdAt: { lt: start } } }),
      this.prisma.artisanProfile.count({ where: { createdAt: { gte: start } } }),
      this.prisma.customerProfile.count({ where: { createdAt: { gte: start } } }),
      this.prisma.serviceRequest.count({ where: { jobStatus: 'IN_PROGRESS' } }),
      this.prisma.serviceRequest.count({
        where: { jobStatus: 'IN_PROGRESS', createdAt: { lt: start } },
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
      this.prisma.transaction.count({ where: { createdAt: { gte: start } } }),
      this.prisma.transaction.count({
        where: { status: 'SUCCESS', createdAt: { gte: start } },
      }),
    ]);

    const revenue = revenueAgg._sum.amount ?? 0;
    const prevRevenue = prevRevenueAgg._sum.amount ?? 0;
    const txnSuccessRate = txnTotal > 0 ? (txnSuccess / txnTotal) * 100 : 0;

    const signupTrend = await this.signupTrend(period);

    return {
      totalUsers,
      usersDelta: this.delta(totalUsers, prevTotalUsers),
      newArtisans,
      newCustomers,
      signupTrend,
      activeJobs,
      jobsDelta: this.delta(activeJobs, prevActiveJobs),
      revenue,
      revenueDelta: this.delta(revenue, prevRevenue),
      txnSuccessRate: Number(txnSuccessRate.toFixed(2)),
      txnSuccessRateDelta: 0,
    };
  }

  private async signupTrend(period: Period): Promise<number[]> {
    const buckets = period === '30d' ? 30 : 7;
    const now = new Date();
    const results: number[] = [];
    for (let i = buckets - 1; i >= 0; i--) {
      const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
      const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
      const count = await this.prisma.user.count({
        where: { createdAt: { gte: dayStart, lt: dayEnd } },
      });
      results.push(count);
    }
    return results;
  }

  private delta(current: number, previous: number): number {
    if (previous === 0) return current > 0 ? 100 : 0;
    return Number((((current - previous) / previous) * 100).toFixed(2));
  }

  // ---------- 2.1 Recent activity ----------
  public async getActivity(limit = 6) {
    const events = await this.prisma.activityEvent.findMany({
      orderBy: { createdAt: 'desc' },
      take: limit,
    });

    const colorFor = (type: string): 'green' | 'red' | 'blue' | 'amber' => {
      if (/fail|reject|ban|dispute/i.test(type)) return 'red';
      if (/complete|approve|success|paid/i.test(type)) return 'green';
      if (/pending|review|warn/i.test(type)) return 'amber';
      return 'blue';
    };

    return events.map((e) => ({
      id: e.id,
      type: e.type,
      text: e.text,
      timestamp: e.createdAt,
      color: colorFor(e.type),
    }));
  }

  // ---------- 2.1 Jobs summary ----------
  public async getJobsSummary() {
    const [completed, inProgress, pending, cancelled] = await Promise.all([
      this.prisma.serviceRequest.count({ where: { jobStatus: 'COMPLETED' } }),
      this.prisma.serviceRequest.count({ where: { jobStatus: 'IN_PROGRESS' } }),
      this.prisma.serviceRequest.count({ where: { jobStatus: 'PENDING' } }),
      this.prisma.serviceRequest.count({ where: { jobStatus: 'CANCELLED' } }),
    ]);

    const total = completed + inProgress + pending + cancelled;
    const completionRate = total > 0 ? Number(((completed / total) * 100).toFixed(2)) : 0;

    return { completed, inProgress, pending, cancelled, completionRate };
  }

  // ---------- 2.1 Health ----------
  public async getHealth() {
    const [txnTotal, txnSuccess, ratingAgg, revenueAgg] = await Promise.all([
      this.prisma.transaction.count(),
      this.prisma.transaction.count({ where: { status: 'SUCCESS' } }),
      this.prisma.artisanProfile.aggregate({ _avg: { rating: true } }),
      this.prisma.transaction.aggregate({
        _sum: { amount: true },
        where: {
          status: 'SUCCESS',
          type: 'PAYMENT',
          createdAt: {
            gte: new Date(new Date().setHours(0, 0, 0, 0)),
          },
        },
      }),
    ]);

    const txnSuccessRate = txnTotal > 0 ? Number(((txnSuccess / txnTotal) * 100).toFixed(2)) : 100;

    return {
      uptime: 99.9,
      txnSuccessRate,
      avgRating: Number((ratingAgg._avg.rating ?? 0).toFixed(2)),
      avgResponseTimeMinutes: 0,
      dailyRevenueGoal: 100000,
      dailyRevenueCurrent: revenueAgg._sum.amount ?? 0,
    };
  }

  // ---------- 2.2 Legacy general stats ----------
  public async getGeneralStats() {
    const [totalCustomers, totalArtisans, activeJobs, failedTransactions, openComplaints] =
      await Promise.all([
        this.prisma.customerProfile.count(),
        this.prisma.artisanProfile.count(),
        this.prisma.serviceRequest.count({ where: { jobStatus: 'IN_PROGRESS' } }),
        this.prisma.transaction.count({ where: { status: 'FAILED' } }),
        this.prisma.complaint.count({ where: { status: { in: ['NEW', 'IN_REVIEW'] } } }),
      ]);

    return { totalCustomers, totalArtisans, activeJobs, failedTransactions, openComplaints };
  }
}
