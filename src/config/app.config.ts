export default () => ({
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: parseInt(process.env.PORT ?? '3000', 10),
  databaseUrl: process.env.DATABASE_URL as string,
  logLevel: process.env.LOG_LEVEL ?? 'info',
  frontendUrl: process.env.FRONTEND_URL ?? 'http://localhost:3002',
  baseUrl: process.env.BASE_URL ?? 'http://localhost:3000',
  emailHost: process.env.EMAIL_HOST,
  emailPort: parseInt(process.env.EMAIL_PORT ?? '587', 10),
  emailUser: process.env.EMAIL_USER,
  emailPass: process.env.EMAIL_PASS,
  emailFrom: process.env.EMAIL_FROM,
});