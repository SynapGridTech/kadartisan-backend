export const artisanApprovalTemplate = (fullName: string): string => {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8" />
    <title>Artisan Application Approved</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f4f6f8; font-family:Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:20px 0;">
      <tr>
        <td align="center">
          <table width="500" cellpadding="0" cellspacing="0" 
            style="background:#ffffff; border-radius:10px; padding:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">

            <tr>
              <td align="center">
                <div style="width:80px; height:80px; background-color:#10b981; border-radius:50%; line-height:80px; text-align:center; margin-bottom:20px;">
                  <span style="font-size:40px; color:#ffffff;">✓</span>
                </div>
                <h2 style="margin:0; color:#111827;">Congratulations, ${fullName}!</h2>
                <p style="color:#6b7280; font-size:14px; margin-top:8px;">
                  Your artisan application has been approved.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:30px 0;">
                <p style="font-size:14px; color:#374151; line-height:1.6;">
                  Dear ${fullName},
                </p>
                <p style="font-size:14px; color:#374151; line-height:1.6;">
                  We're excited to inform you that your artisan profile has been <strong style="color:#10b981;">approved</strong>! 
                  You can now start receiving service requests from customers on KadArtisan.
                </p>
                <p style="font-size:14px; color:#374151; line-height:1.6;">
                  <strong>What's next?</strong>
                </p>
                <ul style="font-size:14px; color:#374151; line-height:1.8;">
                  <li>Complete your profile with portfolio images</li>
                  <li>Set your availability and service areas</li>
                  <li>Start accepting booking requests</li>
                </ul>
              </td>
            </tr>

            <tr>
              <td align="center">
                <p style="font-size:12px; color:#9ca3af; margin-top:20px;">
                  Thank you for joining KadArtisan. We wish you success!
                </p>
                <p style="font-size:11px; color:#9ca3af; margin-top:30px; padding-top:20px; border-top:1px solid #eee;">
                  KadArtisan | <a href="{{unsubscribeUrl}}" style="color:#2563eb; text-decoration:none;">Unsubscribe from notifications</a>
                </p>
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
  </html>
  `;
};