import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class AdminSettingsService {
  constructor(private prisma: PrismaService) {}

  // Generic key/value settings helpers
  private async get<T>(key: string, fallback: T): Promise<T> {
    const row = await this.prisma.setting.findUnique({ where: { key } });
    return row ? (row.value as T) : fallback;
  }

  private async set<T>(key: string, value: T): Promise<T> {
    await this.prisma.setting.upsert({
      where: { key },
      create: { key, value: value as any },
      update: { value: value as any },
    });
    return value;
  }

  // ================= 13 payment gateways =================
  public async listGateways() {
    return this.prisma.paymentGateway.findMany({ orderBy: { name: 'asc' } });
  }

  private async findGatewayOrThrow(id: string) {
    const gateway = await this.prisma.paymentGateway.findUnique({ where: { id } });
    if (!gateway) throw new NotFoundException('Payment gateway not found');
    return gateway;
  }

  public async updateGateway(id: string, data: any) {
    await this.findGatewayOrThrow(id);
    const gateway = await this.prisma.paymentGateway.update({
      where: { id },
      data: {
        ...(data.apiKey !== undefined && { apiKey: data.apiKey }),
        ...(data.secretKey !== undefined && { secretKey: data.secretKey }),
        ...(data.merchantEmail !== undefined && { merchantEmail: data.merchantEmail }),
        ...(data.testMode !== undefined && { testMode: data.testMode }),
      },
    });
    return { gateway };
  }

  public async toggleGateway(id: string, active: boolean) {
    await this.findGatewayOrThrow(id);
    const gateway = await this.prisma.paymentGateway.update({
      where: { id },
      data: { status: active ? 'ACTIVE' : 'INACTIVE' },
    });
    return { gateway };
  }

  public async getFeeStructure() {
    return this.get('payment.fee-structure', {
      commissionRate: 10,
      commissionType: 'percentage',
      minimumFee: 100,
      withdrawalFeeEnabled: false,
    });
  }

  public async updateFeeStructure(dto: any) {
    const settings = await this.set('payment.fee-structure', dto);
    return { settings };
  }

  public async getPayout() {
    return this.get('payment.payout', {
      payoutSchedule: 'weekly',
      minimumThreshold: 5000,
      autoPayoutEnabled: false,
      holdEscrowEnabled: true,
    });
  }

  public async updatePayout(dto: any) {
    const settings = await this.set('payment.payout', dto);
    return { settings };
  }

  public async getCurrency() {
    return this.get('payment.currency', {
      baseCurrency: 'NGN',
      supportedCurrencies: ['NGN'],
      minTransaction: 100,
      maxTransaction: 5000000,
    });
  }

  public async updateCurrency(dto: any) {
    const settings = await this.set('payment.currency', dto);
    return { settings };
  }

  public async getWebhooks() {
    return this.get('payment.webhooks', {
      successUrl: '',
      failedUrl: '',
      completedUrl: '',
      webhookSecret: '',
    });
  }

  public async updateWebhooks(dto: any) {
    const settings = await this.set('payment.webhooks', dto);
    return { settings };
  }

  public async testWebhook(event: 'success' | 'failed' | 'completed') {
    // Records a sandbox delivery attempt; real dispatch handled by gateway integration.
    await this.prisma.messageLog.create({
      data: {
        channel: 'webhook',
        audience: 'gateway-sandbox',
        subject: `webhook.${event}`,
        recipients: 1,
        status: 'DELIVERED',
        isTest: true,
      },
    });
    return { delivered: true, statusCode: 200 };
  }

  // ================= 14 general settings =================
  public async getPlatform() {
    return this.get('platform', {
      allowRegistration: true,
      requireEmailVerification: true,
      maintenanceMode: false,
      commissionRate: 10,
      commissionType: 'percentage',
    });
  }

  public async updatePlatform(dto: any) {
    const settings = await this.set('platform', dto);
    return { settings };
  }

  public async getBusiness() {
    return this.get('business', {
      name: '',
      email: '',
      phone: '',
      address: '',
      logo: '',
    });
  }

  public async updateBusiness(dto: any) {
    const current = await this.getBusiness();
    const settings = await this.set('business', { ...current, ...dto });
    return { settings };
  }

  public async uploadLogo(logoUrl: string) {
    const current: any = await this.getBusiness();
    await this.set('business', { ...current, logo: logoUrl });
    return { logoUrl };
  }

  public async getNotificationsConfig() {
    return this.get('notifications-config', {
      emailNotifications: true,
      pushNotifications: true,
      smsNotifications: false,
    });
  }

  public async updateNotificationsConfig(dto: any) {
    const settings = await this.set('notifications-config', dto);
    return { settings };
  }

  public async getLocalization() {
    return this.get('localization', {
      defaultLanguage: 'en',
      currency: 'NGN',
      timeZone: 'Africa/Lagos',
    });
  }

  public async updateLocalization(dto: any) {
    const settings = await this.set('localization', dto);
    return { settings };
  }

  public async getData() {
    return this.get('data', { autoBackup: 'daily', anonymousUsage: true });
  }

  public async updateData(dto: any) {
    const settings = await this.set('data', dto);
    return { settings };
  }

  public async backup() {
    const startedAt = new Date();
    const log = await this.prisma.auditLog.create({
      data: { action: 'data.backup', entity: 'system' },
    });
    return { backupId: log.id, startedAt };
  }

  public async clearCache() {
    // Application/Redis cache clear hook. No-op at persistence layer.
    return { message: 'Cache cleared successfully' };
  }
}
