import { Injectable } from '@nestjs/common';
import Twilio from 'twilio';

@Injectable()
export class SmsService {
  private client;

  constructor() {
    this.client = Twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN,
    );
  }

  public async sendSms(to: string, message: string) {
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
