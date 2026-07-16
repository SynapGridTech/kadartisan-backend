import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { NotificationService } from './providers/notification.service';
import { EmailService } from './providers/email.service';
import { TestEmailDto } from './dto/test-email.dto';

@ApiTags('Notification')
@Controller('notification')
export class NotificationController {
  constructor(
    private readonly notificationService: NotificationService,
    private readonly emailService: EmailService,
  ) {}

  //__________ TEST EMAIL DELIVERY (public — dev mail pipeline check) ________________________
  @Post('test-email')
  @ApiOperation({
    summary: 'Send a test email to verify the mail pipeline',
    description:
      'Sends a test message via the configured SMTP transport. On the free Ethereal dev ' +
      'transport, mail is captured (not delivered) and a preview URL is returned.',
  })
  @ApiResponse({ status: 201, description: 'Test email dispatched' })
  async testEmail(@Body() dto: TestEmailDto) {
    const previewUrl = await this.emailService.sendTestEmail(
      dto.to,
      dto.subject,
      dto.message,
    );
    return {
      success: true,
      message: `Test email sent to ${dto.to}`,
      previewUrl,
      note: previewUrl
        ? 'Using Ethereal dev transport — open previewUrl to view the captured email (not delivered to a real inbox).'
        : 'Mail dispatched via the configured SMTP transport.',
    };
  }
}