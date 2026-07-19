import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'test', 'staging', 'production').default('development'),
  PORT: Joi.number().default(3000),
  DATABASE_URL: Joi.string().uri().required(),
  LOG_LEVEL: Joi.string().valid('fatal','error','warn','info','debug','trace','silent').default('info'),
  // Email configuration - optional for local development, required in production
  EMAIL_HOST: Joi.string().default('smtp.ethereal.email'), // Ethereal is nodemailer's default test SMTP
  EMAIL_PORT: Joi.number().default(587),
  EMAIL_USER: Joi.string().default('test-user'),
  EMAIL_PASS: Joi.string().default('test-pass'),
  EMAIL_FROM: Joi.string().pattern(/^.*<[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>$|^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/).default('noreply@example.com'),
  // SendGrid HTTPS API key. When set, email is sent via SendGrid (port 443)
  // instead of SMTP — required on hosts that block outbound SMTP ports.
  SENDGRID_API_KEY: Joi.string().optional(),
  RESEND_API_KEY: Joi.string().optional(),
  BASE_URL: Joi.string().uri().default('http://localhost:3000'),
  FRONTEND_URL: Joi.string().custom((value, helpers) => {
    const urls = value.split(',').map(url => url.trim());
    for (const url of urls) {
      const { error } = Joi.string().uri().validate(url);
      if (error) {
        return helpers.error('string.uri');
      }
    }
    return value;
  }).default('http://localhost:3002'),
});