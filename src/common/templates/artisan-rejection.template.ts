export const artisanRejectionTemplate = (fullName: string, reason?: string): string => {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8" />
    <title>Artisan Application Update</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f4f6f8; font-family:Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:20px 0;">
      <tr>
        <td align="center">
          <table width="500" cellpadding="0" cellspacing="0" 
            style="background:#ffffff; border-radius:10px; padding:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">

            <tr>
              <td align="center">
                <div style="width:80px; height:80px; background-color:#f59e0b; border-radius:50%; line-height:80px; text-align:center; margin-bottom:20px;">
                  <span style="font-size:40px; color:#ffffff;">!</span>
                </div>
                <h2 style="margin:0; color:#111827;">Artisan Application Update</h2>
                <p style="color:#6b7280; font-size:14px; margin-top:8px;">
                  Thank you for your interest in joining KadArtisan.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:30px 0;">
                <p style="font-size:14px; color:#374151; line-height:1.6;">
                  Dear ${fullName},
                </p>
                <p style="font-size:14px; color:#374151; line-height:1.6;">
                  We regret to inform you that your artisan application has not been approved at this time.
                </p>
                ${
                  reason
                    ? `
                <div style="background-color:#fef3c7; border-left:4px solid #f59e0b; padding:15px; margin:20px 0;">
                  <p style="font-size:14px; color:#92400e; margin:0;">
                    <strong>Reason:</strong> ${reason}
                  </p>
                </div>
                `
                    : ''
                }
                <p style="font-size:14px; color:#374151; line-height:1.6;">
                  <strong>What can you do?</strong>
                </p>
                <ul style="font-size:14px; color:#374151; line-height:1.8;">
                  <li>Review the reason provided above</li>
                  <li>Make necessary improvements or gather required documents</li>
                  <li>Submit a new application through your dashboard</li>
                </ul>
                <p style="font-size:14px; color:#374151; line-height:1.6;">
                  Don't worry! You can reapply after addressing the concerns mentioned above.
                </p>
              </td>
            </tr>

            <tr>
              <td align="center">
                <p style="font-size:12px; color:#9ca3af; margin-top:20px;">
                  If you have questions, please contact our support team.
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
