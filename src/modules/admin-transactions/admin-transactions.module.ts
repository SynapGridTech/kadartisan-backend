import { Module } from '@nestjs/common';
import {
  AdminTransactionsController,
  AdminRefundsController,
  AdminRefundPolicyController,
} from './admin-transactions.controller';
import { AdminTransactionsService } from './providers/admin-transactions.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [
    AdminTransactionsController,
    AdminRefundsController,
    AdminRefundPolicyController,
  ],
  providers: [AdminTransactionsService],
})
export class AdminTransactionsModule {}
