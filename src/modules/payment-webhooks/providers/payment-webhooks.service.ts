import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class PaymentWebhooksService {
  private readonly logger = new Logger(PaymentWebhooksService.name);

  constructor(private prisma: PrismaService) {}

  private extractReference(payload: any): string | undefined {
    return (
      payload?.reference ??
      payload?.data?.reference ??
      payload?.tx_ref ??
      payload?.data?.tx_ref
    );
  }

  public async handlePaymentSuccess(payload: any) {
    const reference = this.extractReference(payload);
    if (reference) {
      await this.prisma.transaction.updateMany({
        where: { reference },
        data: { status: 'SUCCESS' },
      });
    }
    this.logger.log(`Payment success webhook processed (ref: ${reference ?? 'n/a'})`);
    return { received: true };
  }

  public async handlePaymentFailed(payload: any) {
    const reference = this.extractReference(payload);
    if (reference) {
      await this.prisma.transaction.updateMany({
        where: { reference },
        data: { status: 'FAILED' },
      });
    }
    this.logger.log(`Payment failed webhook processed (ref: ${reference ?? 'n/a'})`);
    return { received: true };
  }

  public async handlePayoutCompleted(payload: any) {
    const reference = this.extractReference(payload);
    if (reference) {
      await this.prisma.transaction.updateMany({
        where: { reference, type: 'PAYOUT' },
        data: { status: 'SUCCESS' },
      });
    }
    this.logger.log(`Payout completed webhook processed (ref: ${reference ?? 'n/a'})`);
    return { received: true };
  }
}
