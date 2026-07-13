import { Module } from '@nestjs/common';
import { PaymentWebhooksController } from './payment-webhooks.controller';
import { PaymentWebhooksService } from './providers/payment-webhooks.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [PaymentWebhooksController],
  providers: [PaymentWebhooksService],
})
export class PaymentWebhooksModule {}
