import { Module } from '@nestjs/common';
import { NotificationController } from './notification.controller';
import { SmsService } from './providers/sms.service';
import { NotificationService } from './providers/notification.service';
import { EmailService } from './providers/email.service';

@Module({
  controllers: [NotificationController],
  providers: [NotificationService, SmsService, EmailService],
  exports: [NotificationService],
})
export class NotificationModule {}
