import { Module } from '@nestjs/common';
import { AdminBadgesController } from './admin-badges.controller';
import { AdminBadgesService } from './providers/admin-badges.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AdminBadgesController],
  providers: [AdminBadgesService],
})
export class AdminBadgesModule {}
