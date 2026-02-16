export const otpEmailTemplate = (otp: string): string => {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8" />
    <title>OTP Verification</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f4f6f8; font-family:Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:20px 0;">
      <tr>
        <td align="center">
          <table width="500" cellpadding="0" cellspacing="0" 
            style="background:#ffffff; border-radius:10px; padding:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">

            <tr>
              <td align="center">
                <h2 style="margin:0; color:#111827;">Verify Your Account</h2>
                <p style="color:#6b7280; font-size:14px; margin-top:8px;">
                  Use the OTP below to complete your verification.
                </p>
              </td>
            </tr>

            <tr>
              <td align="center" style="padding:30px 0;">
                <div style="font-size:32px; font-weight:bold; letter-spacing:6px; color:#2563eb;">
                  ${otp}
                </div>
              </td>
            </tr>

            <tr>
              <td align="center">
                <p style="font-size:14px; color:#6b7280;">
                  This code will expire in <strong>5 minutes</strong>.
                </p>
                <p style="font-size:12px; color:#9ca3af; margin-top:20px;">
                  If you did not request this code, please ignore this email.
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
