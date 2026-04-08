import { Injectable, Logger } from '@nestjs/common';
import { Resend } from 'resend';
import { otpEmailTemplate } from 'src/common/templates/otp-email.template';
import { securityAlertTemplate } from 'src/common/templates/security-alert.template';
import { artisanApprovalTemplate } from 'src/common/templates/artisan-approval.template';
import { artisanRejectionTemplate } from 'src/common/templates/artisan-rejection.template';

@Injectable()
export class EmailService {
  private resend: Resend;
  private readonly logger = new Logger(EmailService.name);

  constructor() {
    this.resend = new Resend(process.env.RESEND_API_KEY);
  }

  // ✅ Generic Mail Sender
  public async sendMail(options: {
    to: string;
    subject: string;
    html: string;
  }) {
    try {
      const { data, error } = await this.resend.emails.send({
        from: process.env.EMAIL_FROM || 'kadArtisan <synapgrid@resend.dev>',
        to: options.to,
        subject: options.subject,
        html: options.html,
      });

      if (error) {
        this.logger.error('Failed to send email:', error);
        throw new Error(`Email sending failed: ${error.message}`);
      }

      this.logger.log(`Email sent successfully: ${data?.id}`);
      return data;
    } catch (error) {
      this.logger.error('Error sending email:', error);
      throw error;
    }
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
