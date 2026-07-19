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
    // For Gmail: use port 465 with secure=true, or port 587 with secure=false (STARTTLS)
    const isGmail = process.env.EMAIL_HOST === 'smtp.gmail.com';
    this.transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT),
      secure: isGmail && Number(process.env.EMAIL_PORT) === 465, // true only for Gmail's SSL port
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      // Force IPv4 to avoid host IPv6 connectivity issues (e.g. Railway has no
      // outbound IPv6 route, so an AAAA result for the SMTP host fails with
      // ENETUNREACH). Applied for all hosts, not just Gmail. The global
      // dns.setDefaultResultOrder('ipv4first') in main.ts is the primary fix;
      // this is defense in depth at the socket level. Spread because `family`
      // is not in @types/nodemailer's transport options.
      ...{ family: 4 },
    });
  }

  // ✅ Generic Mail Sender — returns the Ethereal preview URL when available (dev), else null.
  public async sendMail(options: {
    to: string;
    subject: string;
    html: string;
  }): Promise<string | null> {
    // Add List-Unsubscribe header (required to avoid spam filters for bulk emails)
    // Replace with your actual unsubscribe page URL
    const unsubscribeUrl = `${process.env.BASE_URL || 'http://localhost:3002'}/unsubscribe?email=${encodeURIComponent(options.to)}`;
    
    // Replace placeholder in email templates with actual unsubscribe URL
    const processedHtml = options.html.replace(/{{unsubscribeUrl}}/g, unsubscribeUrl);
    
    const info = await this.transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: options.to,
      subject: options.subject,
      html: processedHtml,
      // Headers that improve email deliverability and avoid spam filters
      headers: {
        'List-Unsubscribe': `<${unsubscribeUrl}>, <mailto:unsubscribe@kadartisan.com?subject=unsubscribe>`,
        'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
        'Precedence': 'bulk', // Prevents auto-replies, good practice
        'X-Auto-Response-Suppress': 'OOF, AutoReply',
      },
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
    // Use the beautiful new test email template you provided, with unsubscribe link
    const testEmailHtml = `<!DOCTYPE html>
<html>
  <body style="margin:0; padding:0; background:#eee7dc; font-family:Georgia, 'Times New Roman', serif; color:#2f2a26;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#eee7dc; padding:56px 0;">
      <tr>
        <td align="center">

          <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background:#fffdfa; border-radius:4px; box-shadow:0 20px 50px rgba(60,40,20,0.10);">

            <!-- Top hairline band -->
            <tr>
              <td style="background:#2b201a; height:6px; line-height:6px; font-size:0;">&nbsp;</td>
            </tr>

            <tr>
              <td style="padding:56px 50px 0;">

                <!-- Monogram -->
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td align="center">
                      <table role="presentation" cellspacing="0" cellpadding="0">
                        <tr>
                          <td style="width:84px; height:84px; border:1px solid #c9a771; border-radius:50%; text-align:center; vertical-align:middle; font-size:30px; letter-spacing:1px; color:#9c6b34; font-family:Georgia, serif;">
                            K
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                </table>

                <!-- Eyebrow -->
                <p style="margin:28px 0 0; text-align:center; font-size:11px; letter-spacing:4px; text-transform:uppercase; color:#a98a5f;">
                  A Warm Welcome
                </p>

                <!-- Headline -->
                <h1 style="margin:10px 0 0; text-align:center; font-size:32px; font-weight:400; letter-spacing:0.5px; color:#241b15; font-family:Georgia, 'Times New Roman', serif;">
                  Welcome to <span style="font-style:italic; color:#9c6b34;">KadArtisan</span>
                </h1>

                <!-- Ornamental divider -->
                <table role="presentation" cellspacing="0" cellpadding="0" style="margin:26px auto 0;">
                  <tr>
                    <td style="width:36px; height:1px; background:#d9c19a; font-size:0; line-height:0;">&nbsp;</td>
                    <td style="padding:0 10px; font-size:13px; color:#c9a771;">&#10022;</td>
                    <td style="width:36px; height:1px; background:#d9c19a; font-size:0; line-height:0;">&nbsp;</td>
                  </tr>
                </table>

                <!-- Body copy -->
                <p style="margin:30px 0 0; text-align:center; font-size:16px; line-height:1.85; color:#4a423a;">
                  ${message ?? 'Thank you for joining us. We are delighted to welcome you into<br>a world shaped by thoughtful craftsmanship, quiet detail,<br>and a devotion to timeless elegance.'}
                </p>

                <!-- CTA -->
                <table role="presentation" cellspacing="0" cellpadding="0" style="margin:38px auto 0;">
                  <tr>
                    <td style="background:#241b15; border-radius:2px;">
                      <a href="#" style="display:inline-block; padding:14px 40px; font-size:12px; letter-spacing:3px; text-transform:uppercase; color:#f3ead9; text-decoration:none; font-family:Georgia, serif;">
                        Discover the Collection
                      </a>
                    </td>
                  </tr>
                </table>

              </td>
            </tr>

            <!-- Signature -->
            <tr>
              <td style="padding:48px 50px 20px; text-align:center;">
                <p style="margin:0; font-size:14px; font-style:italic; color:#8a7c6b;">With warm regards,</p>
                <p style="margin:6px 0 0; font-size:14px; letter-spacing:1.5px; text-transform:uppercase; color:#9c6b34;">The KadArtisan Team</p>
              </td>
            </tr>

            <!-- Footer divider -->
            <tr>
              <td style="padding:0 50px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td style="height:1px; background:#ece2d3; font-size:0; line-height:0;">&nbsp;</td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:22px 50px 44px; text-align:center;">
                <p style="margin:0; font-size:11px; letter-spacing:2px; text-transform:uppercase; color:#b7ac9d;">
                  KadArtisan &nbsp;&middot;&nbsp; Crafted with Care
                </p>
                <!-- Unsubscribe link added for spam compliance -->
                <p style="font-size:11px; color:#9ca3af; margin-top:20px; padding-top:20px; border-top:1px solid #eee;">
                  <a href="{{unsubscribeUrl}}" style="color:#9c6b34; text-decoration:none;">Unsubscribe from notifications</a>
                </p>
              </td>
            </tr>

          </table>

          <!-- Bottom micro-note -->
          <table role="presentation" width="600" cellspacing="0" cellpadding="0">
            <tr>
              <td style="padding:24px 20px 0; text-align:center;">
                <p style="margin:0; font-size:11px; color:#a99c8a;">
                  You're receiving this email because you joined KadArtisan.
                </p>
              </td>
            </tr>
          </table>

        </td>
      </tr>
    </table>
  </body>
</html>`;

    return this.sendMail({
      to,
      subject: subject ?? 'KadArtisan Test Email',
      html: testEmailHtml,
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