import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { otpEmailTemplate } from 'src/common/templates/otp-email.template';
import { securityAlertTemplate } from 'src/common/templates/security-alert.template';
// import { otpEmailTemplate } from 'src/common/templates/email/otp-email.template';
// import { securityAlertTemplate } from 'src/common/templates/email/security-alert.template';

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

  // ✅ Generic Mail Sender
  public async sendMail(options: {
    to: string;
    subject: string;
    html: string;
  }) {
    await this.transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: options.to,
      subject: options.subject,
      html: options.html,
    });
  }

  // ✅ OTP Email
  public async sendOtpEmail(to: string, otp: string) {
    await this.sendMail({
      to,
      subject: 'Your Verification Code',
      html: otpEmailTemplate(otp),
    });
  }

  // ✅ Security Alert Email
  public async sendSecurityAlertEmail(
    to: string,
    fullName: string,
    lockUntil: Date,
  ) {
    await this.sendMail({
      to,
      subject: '⚠ Account Locked - Security Alert',
      html: securityAlertTemplate(fullName, lockUntil),
    });
  }
}
