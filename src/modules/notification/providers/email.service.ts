import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { otpEmailTemplate } from 'src/common/templates/otp-email.template';
import { securityAlertTemplate } from 'src/common/templates/security-alert.template';
import { artisanApprovalTemplate } from 'src/common/templates/artisan-approval.template';
import { artisanRejectionTemplate } from 'src/common/templates/artisan-rejection.template';

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

  // ✅ Generic Mail Sender — returns the Ethereal preview URL when available (dev), else null.
  public async sendMail(options: {
    to: string;
    subject: string;
    html: string;
  }): Promise<string | null> {
    const info = await this.transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: options.to,
      subject: options.subject,
      html: options.html,
    });

    // When using Ethereal (free dev SMTP), no mail is actually delivered —
    // nodemailer exposes a preview URL to view the captured message instead.
    const previewUrl = nodemailer.getTestMessageUrl(info);
    if (previewUrl) {
      console.log(`📧 Email preview (Ethereal) for "${options.subject}" → ${previewUrl}`);
    }
    return previewUrl || null;
  }

  // ✅ Test Email — used by the mail notification test endpoint
  public async sendTestEmail(to: string, subject?: string, message?: string) {
    return this.sendMail({
      to,
      subject: subject ?? 'KadArtisan Test Email',
      html: `<div style="font-family:sans-serif">
        <h2>KadArtisan mail test ✅</h2>
        <p>${message ?? 'This is a test email from the KadArtisan notification service.'}</p>
      </div>`,
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

  // ✅ Artisan Approval Email
  public async sendArtisanApprovalEmail(to: string, fullName: string) {
    await this.sendMail({
      to,
      subject: '🎉 Your Artisan Application Has Been Approved!',
      html: artisanApprovalTemplate(fullName),
    });
  }

  // ✅ Artisan Rejection Email
  public async sendArtisanRejectionEmail(
    to: string,
    fullName: string,
    reason?: string,
  ) {
    await this.sendMail({
      to,
      subject: 'Artisan Application Update',
      html: artisanRejectionTemplate(fullName, reason),
    });
  }
}
