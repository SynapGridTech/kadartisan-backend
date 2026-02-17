import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { otpEmailTemplate } from 'src/common/templates/otp-email.template';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT),
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  public async sendOtpEmail(to: string, otp: string) {
  await this.transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject: 'Your Verification Code',
    html: otpEmailTemplate(otp),
  });
}

}
