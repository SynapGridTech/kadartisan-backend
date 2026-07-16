import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HealthController, PrismaHealthIndicator, EmailHealthIndicator } from './health.controller';
import { PrismaModule } from '../database/prisma.module';
import { NotificationModule } from '../modules/notification/notification.module';

@Module({
  imports: [TerminusModule, PrismaModule, NotificationModule],
  controllers: [HealthController],
  providers: [PrismaHealthIndicator, EmailHealthIndicator],
})
export class HealthModule {}