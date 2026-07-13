import { Module } from '@nestjs/common';
import { AdminAppealsController } from './admin-appeals.controller';
import { AdminAppealsService } from './providers/admin-appeals.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AdminAppealsController],
  providers: [AdminAppealsService],
})
export class AdminAppealsModule {}
