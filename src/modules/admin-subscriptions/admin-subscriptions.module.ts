import { Module } from '@nestjs/common';
import {
  AdminSubscriptionPlansController,
  AdminSubscriptionsController,
  AdminUserSubscriptionController,
} from './admin-subscriptions.controller';
import { AdminSubscriptionsService } from './providers/admin-subscriptions.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [
    AdminSubscriptionPlansController,
    AdminSubscriptionsController,
    AdminUserSubscriptionController,
  ],
  providers: [AdminSubscriptionsService],
})
export class AdminSubscriptionsModule {}
