import { Module } from '@nestjs/common';
import { AdminCommunicationsController } from './admin-communications.controller';
import { AdminCommunicationsService } from './providers/admin-communications.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AdminCommunicationsController],
  providers: [AdminCommunicationsService],
})
export class AdminCommunicationsModule {}
