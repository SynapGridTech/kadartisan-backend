export const securityAlertTemplate = (fullName: string, lockUntil: Date) => {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8" />
    <title>Security Alert - Account Locked</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f4f6f8; font-family:Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:20px 0;">
      <tr>
        <td align="center">
          <table width="500" cellpadding="0" cellspacing="0" 
            style="background:#ffffff; border-radius:10px; padding:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">

            <tr>
              <td align="center">
                <h2 style="margin:0; color:#d9534f;">⚠ Security Alert</h2>
              </td>
            </tr>

            <tr>
              <td style="padding-top:20px;">
                <p>Hi <strong>${fullName}</strong>,</p>
                <p>Your account has been temporarily locked due to <strong>3 failed login attempts</strong>.</p>
                <p>The account will automatically unlock at: <strong>${lockUntil.toLocaleString()}</strong></p>
                <p>If this wasn’t you, we strongly recommend resetting your password immediately.</p>
              </td>
            </tr>

            <tr>
              <td align="center">
                <p style="font-size:11px; color:#9ca3af; margin-top:30px; padding-top:20px; border-top:1px solid #eee;">
                  If you need assistance, please contact our support team.<br>
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