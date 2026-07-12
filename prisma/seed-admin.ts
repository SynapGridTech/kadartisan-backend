/**
 * Admin-surface seed — populates the new tables added for the KadArtisan Admin API
 * (badges, transactions, complaints, disputes, subscriptions, communications,
 *  settings, security, FAQs/support, jobs/escrow, activity/reviews/posts).
 *
 * Idempotent: each block is guarded by a row-count check, so re-running only
 * fills empty tables and never duplicates data. Reuses existing Users/Artisans/Skills.
 */
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import 'dotenv/config';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
const prisma = new PrismaClient({ adapter: new PrismaPg(pool) });

const DAY = 24 * 60 * 60 * 1000;
const daysAgo = (n: number) => new Date(Date.now() - n * DAY);
const pick = <T>(arr: T[], i: number): T => arr[i % arr.length];

async function seedSettings() {
  const defaults: Record<string, any> = {
    platform: {
      allowRegistration: true,
      requireEmailVerification: true,
      maintenanceMode: false,
      commissionRate: 10,
      commissionType: 'percentage',
    },
    business: {
      name: 'KadArtisan Ltd',
      email: 'hello@kadartisan.com',
      phone: '+2348012345678',
      address: '12 Ahmadu Bello Way, Kaduna',
      logo: '',
    },
    'notifications-config': {
      emailNotifications: true,
      pushNotifications: true,
      smsNotifications: false,
    },
    localization: { defaultLanguage: 'en', currency: 'NGN', timeZone: 'Africa/Lagos' },
    data: { autoBackup: 'daily', anonymousUsage: true },
    'payment.fee-structure': {
      commissionRate: 10,
      commissionType: 'percentage',
      minimumFee: 100,
      withdrawalFeeEnabled: false,
    },
    'payment.payout': {
      payoutSchedule: 'weekly',
      minimumThreshold: 5000,
      autoPayoutEnabled: false,
      holdEscrowEnabled: true,
    },
    'payment.currency': {
      baseCurrency: 'NGN',
      supportedCurrencies: ['NGN', 'USD'],
      minTransaction: 100,
      maxTransaction: 5000000,
    },
    'payment.webhooks': {
      successUrl: 'https://api.kadartisan.com/webhooks/payment/success',
      failedUrl: 'https://api.kadartisan.com/webhooks/payment/failed',
      completedUrl: 'https://api.kadartisan.com/webhooks/payout/completed',
      webhookSecret: 'whsec_demo_secret',
    },
    'security.authentication': {
      twoFactorEnabled: false,
      loginAlertsEnabled: true,
      passwordPolicy: 'strong',
    },
    'security.firewall': { ipWhitelistEnabled: false, rateLimitEnabled: true },
    'security.data-protection': {
      encryptionEnabled: true,
      gdprEnabled: true,
      backupStorage: 'cloud',
    },
  };

  let created = 0;
  for (const [key, value] of Object.entries(defaults)) {
    const existing = await prisma.setting.findUnique({ where: { key } });
    if (!existing) {
      await prisma.setting.create({ data: { key, value } });
      created++;
    }
  }
  console.log(`⚙️  Settings: ${created} created, ${Object.keys(defaults).length - created} existing`);
}

async function seedPaymentGateways() {
  if ((await prisma.paymentGateway.count()) > 0) {
    console.log('💳 Payment gateways already seeded — skipping');
    return;
  }
  await prisma.paymentGateway.createMany({
    data: [
      { name: 'Paystack', merchantEmail: 'payments@kadartisan.com', testMode: true, status: 'ACTIVE' },
      { name: 'Flutterwave', merchantEmail: 'payments@kadartisan.com', testMode: true, status: 'INACTIVE' },
    ],
  });
  console.log('💳 Payment gateways seeded (Paystack, Flutterwave)');
}

async function seedSkillCategories() {
  const cats = await prisma.skill.findMany({
    where: { category: { not: null } },
    distinct: ['category'],
    select: { category: true },
  });
  let created = 0;
  for (const { category } of cats) {
    if (!category) continue;
    const existing = await prisma.skillCategory.findUnique({ where: { name: category } });
    if (!existing) {
      const cat = await prisma.skillCategory.create({ data: { name: category } });
      await prisma.skill.updateMany({
        where: { category },
        data: { categoryRefId: cat.id },
      });
      created++;
    }
  }
  console.log(`🏷️  Skill categories: ${created} created`);
}

async function seedSubscriptions(artisanUserIds: string[]) {
  let plans = await prisma.subscriptionPlan.findMany();
  if (plans.length === 0) {
    await prisma.subscriptionPlan.createMany({
      data: [
        { name: 'Free', description: 'Starter tier', price: 0, interval: 'MONTHLY', features: ['3 bids/month'], jobLimit: 3 },
        { name: 'Pro', description: 'For growing artisans', price: 5000, interval: 'MONTHLY', features: ['Unlimited bids', 'Priority listing'], jobLimit: null },
        { name: 'Premium', description: 'Full access', price: 12000, interval: 'MONTHLY', features: ['Unlimited bids', 'Verified badge', 'Priority support'], jobLimit: null },
      ],
    });
    plans = await prisma.subscriptionPlan.findMany();
    console.log('📦 Subscription plans seeded (Free, Pro, Premium)');
  } else {
    console.log('📦 Subscription plans already seeded — skipping plans');
  }

  if ((await prisma.subscription.count()) > 0) {
    console.log('🧾 Subscriptions already seeded — skipping');
    return;
  }
  const paid = plans.filter((p) => p.price > 0);
  let i = 0;
  for (const userId of artisanUserIds.slice(0, 6)) {
    const plan = pick(paid, i);
    const sub = await prisma.subscription.create({
      data: {
        userId,
        planId: plan.id,
        status: i % 4 === 3 ? 'EXPIRED' : 'ACTIVE',
        startedAt: daysAgo(30 - i),
        expiresAt: i % 4 === 3 ? daysAgo(1) : new Date(Date.now() + (15 + i) * DAY),
      },
    });
    if (i === 0) {
      await prisma.subscriptionNote.create({
        data: { subscriptionId: sub.id, content: 'Onboarded via referral programme.' },
      });
    }
    i++;
  }
  console.log(`🧾 Subscriptions seeded for ${Math.min(6, artisanUserIds.length)} artisans`);
}

async function seedBadges(artisanUserIds: string[]) {
  if ((await prisma.badge.count()) > 0) {
    console.log('🎖️  Badges already seeded — skipping');
    return;
  }
  let i = 0;
  for (const userId of artisanUserIds.slice(0, 5)) {
    const type = i % 2 === 0 ? 'VERIFIED' : 'TOP_ARTISAN';
    const status = i % 3 === 0 ? 'PENDING' : i % 3 === 1 ? 'ACTIVE' : 'REVOKED';
    await prisma.badge.create({
      data: {
        userId,
        type: type as any,
        status: status as any,
        note: status === 'ACTIVE' ? 'Documents verified.' : status === 'PENDING' ? 'Awaiting review.' : 'Revoked after audit.',
        awardedAt: status === 'ACTIVE' ? daysAgo(i) : null,
        revokedAt: status === 'REVOKED' ? daysAgo(i) : null,
        createdAt: daysAgo(10 - i),
      },
    });
    i++;
  }
  console.log('🎖️  Badges seeded');
}

async function seedJobs(
  customers: { userId: string; profileId: string }[],
  artisans: { userId: string; profileId: string }[],
) {
  if ((await prisma.serviceRequest.count()) > 0) {
    console.log('🛠️  Jobs (ServiceRequest) already present — skipping job seed');
    return [];
  }
  const categories = ['Plumbing', 'Electrical Installation', 'Tailoring', 'Carpentry', 'Painting'];
  const statuses: any[] = ['PENDING', 'IN_PROGRESS', 'IN_PROGRESS', 'COMPLETED', 'COMPLETED', 'CANCELLED'];
  const jobs: string[] = [];

  for (let i = 0; i < 8; i++) {
    const customer = pick(customers, i);
    const artisan = pick(artisans, i);
    const jobStatus = pick(statuses, i);
    const assigned = jobStatus !== 'PENDING';
    const job = await prisma.serviceRequest.create({
      data: {
        customerId: customer.profileId,
        acceptedArtisanId: assigned ? artisan.profileId : null,
        category: pick(categories, i),
        description: `Need a professional for ${pick(categories, i).toLowerCase()} work — job #${i + 1}.`,
        budget: 15000 + i * 5000,
        location: 'Kaduna North',
        state: 'Kaduna',
        lga: 'Kaduna North',
        preferredSkills: [pick(categories, i)],
        title: `${pick(categories, i)} request`,
        urgency: i % 2 === 0 ? 'high' : 'normal',
        status: jobStatus === 'PENDING' ? 'OPEN' : jobStatus === 'COMPLETED' ? 'COMPLETED' : jobStatus === 'CANCELLED' ? 'CANCELLED' : 'IN_PROGRESS',
        jobStatus,
        disputeState: i === 2 ? 'OPEN' : 'NONE',
        disputeReason: i === 2 ? 'Customer disputes work quality.' : null,
        createdAt: daysAgo(20 - i * 2),
      },
    });
    jobs.push(job.id);

    if (assigned) {
      await prisma.escrow.create({
        data: {
          jobId: job.id,
          amount: 15000 + i * 5000,
          status: jobStatus === 'COMPLETED' ? 'RELEASED' : 'HELD',
        },
      });
      await prisma.milestone.createMany({
        data: [
          { jobId: job.id, title: 'Initial assessment', amount: 5000, completed: true },
          { jobId: job.id, title: 'Work completion', amount: 10000 + i * 5000, completed: jobStatus === 'COMPLETED' },
        ],
      });
    }
    if (i === 2) {
      await prisma.disputeNote.create({
        data: { jobId: job.id, content: 'Escalated to review; awaiting customer photos.' },
      });
    }
  }
  console.log('🛠️  Jobs seeded (8 with escrow/milestones)');
  return jobs;
}

async function seedTransactions(
  customers: { userId: string }[],
  artisans: { userId: string }[],
) {
  if ((await prisma.transaction.count()) > 0) {
    console.log('💰 Transactions already seeded — skipping');
    return;
  }
  const gateways = ['Paystack', 'Flutterwave'];
  const statuses: any[] = ['SUCCESS', 'SUCCESS', 'SUCCESS', 'PENDING', 'FAILED', 'STUCK'];
  let ref = 1000;
  const created: { id: string; status: string }[] = [];

  for (let i = 0; i < 12; i++) {
    const customer = pick(customers, i);
    const status = pick(statuses, i);
    const amount = 10000 + i * 2500;
    const txn = await prisma.transaction.create({
      data: {
        reference: `KAD-PAY-${ref++}`,
        userId: customer.userId,
        type: 'PAYMENT',
        status,
        amount,
        currency: 'NGN',
        platformFee: Math.round(amount * 0.1),
        gateway: pick(gateways, i),
        description: `Payment for service #${i + 1}`,
        createdAt: daysAgo(14 - i),
      },
    });
    created.push({ id: txn.id, status });
  }

  // Payouts (one failed to surface on the attention panel)
  for (let i = 0; i < 4; i++) {
    const artisan = pick(artisans, i);
    await prisma.transaction.create({
      data: {
        reference: `KAD-OUT-${ref++}`,
        userId: artisan.userId,
        type: 'PAYOUT',
        status: i === 3 ? 'FAILED' : 'SUCCESS',
        amount: 20000 + i * 3000,
        currency: 'NGN',
        gateway: 'Paystack',
        description: `Artisan payout #${i + 1}`,
        createdAt: daysAgo(7 - i),
      },
    });
  }

  // A refund against the first successful payment
  const firstSuccess = created.find((t) => t.status === 'SUCCESS');
  if (firstSuccess) {
    await prisma.refund.create({
      data: {
        transactionId: firstSuccess.id,
        amount: 5000,
        reason: 'Partial refund — service incomplete',
        status: 'COMPLETED',
        idempotencyKey: 'seed-refund-0001',
        gatewayRef: 'rf_demo_0001',
      },
    });
  }
  console.log('💰 Transactions (16) + 1 refund seeded');
}

async function seedComplaints(users: { id: string }[]) {
  if ((await prisma.complaint.count()) > 0) {
    console.log('📣 Complaints already seeded — skipping');
    return;
  }
  const statuses: any[] = ['NEW', 'IN_REVIEW', 'ESCALATED', 'RESOLVED', 'CLOSED_INVALID'];
  for (let i = 0; i < 5; i++) {
    const filedBy = pick(users, i);
    const against = pick(users, i + 3);
    const status = pick(statuses, i);
    const complaint = await prisma.complaint.create({
      data: {
        filedById: filedBy.id,
        againstId: against.id,
        subject: `Complaint #${i + 1}: ${['Poor quality', 'No-show', 'Overcharged', 'Late delivery', 'Spam'][i]}`,
        description: 'Detailed description of the reported issue for admin review.',
        status,
        escalated: status === 'ESCALATED',
        outcome: status === 'RESOLVED' ? 'refund_issued' : null,
        resolutionNotes: status === 'RESOLVED' ? 'Refund processed and customer notified.' : null,
        closeReason: status === 'CLOSED_INVALID' ? 'Duplicate report.' : null,
        createdAt: daysAgo(12 - i * 2),
      },
    });
    await prisma.complaintNote.create({
      data: { complaintId: complaint.id, content: 'Initial triage note.' },
    });

    // Attach a dispute to the escalated complaint
    if (status === 'ESCALATED') {
      const dispute = await prisma.dispute.create({
        data: { complaintId: complaint.id, status: 'OPEN', frozenAmount: 25000 },
      });
      await prisma.disputeEvidence.create({
        data: { disputeId: dispute.id, label: 'Chat transcript', note: 'Shows agreed scope.' },
      });
      await prisma.disputeNoteEntry.create({
        data: { disputeId: dispute.id, content: 'Both parties contacted for statements.' },
      });
    }
  }
  console.log('📣 Complaints (5) + 1 dispute seeded');
}

async function seedAppeals() {
  // Appeal has @unique userId; only seed if none exist to avoid clashing with real appeals.
  if ((await prisma.appeal.count()) > 0) {
    console.log('📄 Appeals already present — skipping');
    return;
  }
  const suspended = await prisma.user.findMany({
    where: { role: { not: 'ADMIN' } },
    take: 2,
    select: { id: true },
  });
  let i = 0;
  for (const u of suspended) {
    await prisma.appeal.create({
      data: {
        userId: u.id,
        reason: 'I believe the action against my account was a mistake.',
        status: i === 0 ? 'PENDING' : 'IN_REVIEW',
        type: i === 0 ? 'SUSPENSION' : 'VERIFICATION',
        urgent: i === 0,
      },
    });
    i++;
  }
  console.log(`📄 Appeals seeded (${i})`);
}

async function seedCommunications() {
  if ((await prisma.messageTemplate.count()) === 0) {
    await prisma.messageTemplate.createMany({
      data: [
        { name: 'Welcome Email', subject: 'Welcome to KadArtisan', body: 'Hello {{name}}, welcome aboard!', channels: ['email'], type: 'SYSTEM' },
        { name: 'Verification Approved', subject: 'You are verified', body: 'Congrats {{name}}, your KYC is approved.', channels: ['email', 'push'], type: 'SYSTEM' },
        { name: 'Promo Blast', subject: 'Special offer', body: 'Enjoy 10% off Pro this month.', channels: ['email', 'sms'], type: 'ADMIN' },
      ],
    });
    console.log('✉️  Message templates seeded (3)');
  } else {
    console.log('✉️  Message templates already seeded — skipping');
  }

  if ((await prisma.messageLog.count()) === 0) {
    const statuses: any[] = ['DELIVERED', 'DELIVERED', 'READ', 'BOUNCED', 'FAILED'];
    for (let i = 0; i < 5; i++) {
      await prisma.messageLog.create({
        data: {
          channel: i % 2 === 0 ? 'email' : 'push',
          audience: 'all',
          subject: `Broadcast #${i + 1}`,
          body: 'Platform announcement body.',
          recipients: 100 + i * 25,
          status: pick(statuses, i),
          createdAt: daysAgo(6 - i),
        },
      });
    }
    console.log('📨 Message logs seeded (5)');
  } else {
    console.log('📨 Message logs already seeded — skipping');
  }
}

async function seedSupport() {
  if ((await prisma.faq.count()) === 0) {
    await prisma.faq.createMany({
      data: [
        { question: 'How do I reset my password?', answer: 'Use the forgot-password link on the login screen.', published: true },
        { question: 'How are payments secured?', answer: 'Payments are held in escrow until job completion.', published: true },
        { question: 'How do I become a verified artisan?', answer: 'Submit your KYC documents from your profile.', published: false },
      ],
    });
    console.log('❓ FAQs seeded (3)');
  } else {
    console.log('❓ FAQs already seeded — skipping');
  }

  if ((await prisma.knowledgeArticle.count()) === 0) {
    await prisma.knowledgeArticle.createMany({
      data: [
        { title: 'Issuing Refunds', summary: 'Steps for admin refunds', content: 'Full guide to processing refunds.', category: 'Payments' },
        { title: 'Handling Disputes', summary: 'Dispute resolution workflow', content: 'How to resolve escrow disputes.', category: 'Disputes' },
      ],
    });
    console.log('📚 Knowledge base seeded (2)');
  } else {
    console.log('📚 Knowledge base already seeded — skipping');
  }

  if ((await prisma.supportTicket.count()) === 0) {
    const user = await prisma.user.findFirst({ where: { role: { not: 'ADMIN' } }, select: { id: true } });
    const statuses: any[] = ['OPEN', 'IN_PROGRESS', 'RESOLVED'];
    for (let i = 0; i < 3; i++) {
      const ticket = await prisma.supportTicket.create({
        data: {
          userId: user?.id ?? null,
          subject: `Support request #${i + 1}`,
          priority: pick(['low', 'medium', 'high'], i),
          status: pick(statuses, i),
          createdAt: daysAgo(5 - i),
        },
      });
      await prisma.supportMessage.create({
        data: { ticketId: ticket.id, sender: 'user', message: 'I need help with my account.' },
      });
      if (i > 0) {
        await prisma.supportMessage.create({
          data: { ticketId: ticket.id, sender: 'admin', message: 'Thanks for reaching out — looking into it.' },
        });
      }
    }
    console.log('🎫 Support tickets seeded (3)');
  } else {
    console.log('🎫 Support tickets already seeded — skipping');
  }
}

async function seedActivityAndSocial(users: { id: string }[]) {
  if ((await prisma.activityEvent.count()) === 0) {
    const events = [
      { type: 'signup', text: 'New customer registered' },
      { type: 'job_completed', text: 'Job marked as completed' },
      { type: 'payment_success', text: 'Payment received successfully' },
      { type: 'kyc_pending', text: 'Artisan submitted KYC for review' },
      { type: 'payout_failed', text: 'Artisan payout failed' },
      { type: 'complaint_filed', text: 'New complaint filed against artisan' },
    ];
    for (let i = 0; i < events.length; i++) {
      await prisma.activityEvent.create({
        data: { userId: pick(users, i).id, ...events[i], createdAt: daysAgo(0.1 * i) },
      });
    }
    console.log('📈 Activity events seeded (6)');
  } else {
    console.log('📈 Activity events already seeded — skipping');
  }

  if ((await prisma.review.count()) === 0 && users.length >= 2) {
    for (let i = 0; i < 4; i++) {
      await prisma.review.create({
        data: {
          authorId: pick(users, i).id,
          subjectId: pick(users, i + 1).id,
          rating: 3 + (i % 3),
          comment: 'Great, professional service.',
          createdAt: daysAgo(8 - i),
        },
      });
    }
    console.log('⭐ Reviews seeded (4)');
  }

  if ((await prisma.post.count()) === 0) {
    for (let i = 0; i < 3; i++) {
      await prisma.post.create({
        data: { userId: pick(users, i).id, caption: `Recent work sample #${i + 1}`, imageUrl: `/uploads/posts/sample${i + 1}.jpg` },
      });
    }
    console.log('🖼️  Posts seeded (3)');
  }

  if ((await prisma.adminNote.count()) === 0 && users.length > 0) {
    await prisma.adminNote.create({
      data: { subjectId: users[0].id, content: 'Verified identity via phone call. Trusted account.' },
    });
    console.log('📝 Admin note seeded (1)');
  }
}

async function seedSecurity() {
  if ((await prisma.firewallIp.count()) === 0) {
    await prisma.firewallIp.createMany({
      data: [
        { ip: '196.220.0.10', label: 'Head office' },
        { ip: '105.112.0.20', label: 'Ops VPN' },
      ],
    });
    console.log('🛡️  Firewall IPs seeded (2)');
  }
  if ((await prisma.auditLog.count()) === 0) {
    await prisma.auditLog.createMany({
      data: [
        { action: 'settings.update', entity: 'platform', metadata: { field: 'maintenanceMode' } },
        { action: 'admin.login', entity: 'session' },
        { action: 'user.suspend', entity: 'User' },
      ],
    });
    console.log('🧾 Audit logs seeded (3)');
  }
  const admin = await prisma.user.findFirst({ where: { role: 'ADMIN' }, select: { id: true } });
  if (admin && (await prisma.adminSession.count()) === 0) {
    await prisma.adminSession.createMany({
      data: [
        { adminId: admin.id, device: 'Chrome on Windows', ip: '196.220.0.10' },
        { adminId: admin.id, device: 'Safari on iPhone', ip: '105.112.0.20' },
      ],
    });
    console.log('🔐 Admin sessions seeded (2)');
  }
}

async function main() {
  console.log('🌱 Seeding admin-surface data...');

  const allUsers = await prisma.user.findMany({
    where: { deletedAt: null },
    select: {
      id: true,
      role: true,
      customerProfile: { select: { id: true } },
      artisanProfile: { select: { id: true } },
    },
  });
  const nonAdmin = allUsers.filter((u) => u.role !== 'ADMIN');

  const customers = allUsers
    .filter((u) => u.customerProfile)
    .map((u) => ({ userId: u.id, profileId: u.customerProfile!.id }));
  const artisans = allUsers
    .filter((u) => u.artisanProfile)
    .map((u) => ({ userId: u.id, profileId: u.artisanProfile!.id }));

  if (customers.length === 0 || artisans.length === 0) {
    console.warn('⚠️  Not enough customer/artisan profiles to seed jobs & transactions fully.');
  }

  await seedSettings();
  await seedPaymentGateways();
  await seedSkillCategories();
  await seedSubscriptions(artisans.map((a) => a.userId));
  await seedBadges(artisans.map((a) => a.userId));
  if (customers.length && artisans.length) {
    await seedJobs(customers, artisans);
    await seedTransactions(customers, artisans);
  }
  await seedComplaints(nonAdmin);
  await seedAppeals();
  await seedCommunications();
  await seedSupport();
  await seedActivityAndSocial(nonAdmin);
  await seedSecurity();

  console.log('🎉 Admin-surface seed completed!');
}

main()
  .catch((e) => {
    console.error('❌ Admin seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
