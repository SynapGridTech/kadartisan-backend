export const securityAlertTemplate = (fullName: string, lockUntil: Date) => {
  return `
  <div style="font-family: Arial, sans-serif; padding:20px;">
    <h2 style="color:#d9534f;">⚠ Security Alert</h2>

    <p>Hi <strong>${fullName}</strong>,</p>

    <p>
      Your account has been temporarily locked due to 
      <strong>3 failed login attempts</strong>.
    </p>

    <p>
      The account will automatically unlock at:
      <strong>${lockUntil.toLocaleString()}</strong>
    </p>

    <p>
      If this wasn’t you, we strongly recommend resetting your password immediately.
    </p>

    <hr />
    <small>
      If you need assistance, please contact our support team.
    </small>
  </div>
  `;
};
