import { Module } from '@nestjs/common';
import {
  AdminFaqsController,
  AdminKnowledgeBaseController,
  AdminSupportTicketsController,
} from './admin-support.controller';
import { AdminSupportService } from './providers/admin-support.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [
    AdminFaqsController,
    AdminKnowledgeBaseController,
    AdminSupportTicketsController,
  ],
  providers: [AdminSupportService],
})
export class AdminSupportModule {}
