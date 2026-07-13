import { Module } from '@nestjs/common';
import {
  AdminComplaintsController,
  AdminDisputesController,
} from './admin-complaints.controller';
import { AdminComplaintsService } from './providers/admin-complaints.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AdminComplaintsController, AdminDisputesController],
  providers: [AdminComplaintsService],
})
export class AdminComplaintsModule {}
