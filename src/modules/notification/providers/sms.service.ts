import { Injectable, Logger } from '@nestjs/common';
import Twilio from 'twilio';

@Injectable()
export class SmsService {
  private readonly logger = new Logger(SmsService.name);
  private client: ReturnType<typeof Twilio> | null = null;

  constructor() {
    const sid = process.env.TWILIO_ACCOUNT_SID;
    const token = process.env.TWILIO_AUTH_TOKEN;

    // Twilio account SIDs always start with "AC". When creds are absent or clearly
    // invalid we skip client init and fall back to dev log mode (below) so the app
    // boots and OTP flows stay testable without a paid SMS provider.
    if (sid && token && sid.startsWith('AC')) {
      try {
        this.client = Twilio(sid, token);
      } catch (error) {
        this.logger.warn(
          `Twilio init failed (${(error as Error).message}); using dev log SMS mode.`,
        );
        this.client = null;
      }
    } else {
      this.logger.warn(
        'Twilio credentials not configured — using dev log SMS mode (codes printed to console, not delivered).',
      );
    }
  }

  public async sendSms(to: string, message: string): Promise<boolean> {
    // Dev fallback: no real provider configured.
    if (!this.client) {
      this.logger.log(`📱 [DEV SMS] to ${to}: ${message}`);
      return true;
    }

    try {
      await this.client.messages.create({
        body: message,
        from: process.env.TWILIO_PHONE_NUMBER,
        to,
      });

      return true;
    } catch (error) {
      console.error('SMS sending failed:', error);
      throw new Error('Failed to send SMS');
    }
  }
}
