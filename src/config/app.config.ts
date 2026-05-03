export default () => ({
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: parseInt(process.env.PORT ?? '3000', 10),
  databaseUrl: process.env.DATABASE_URL as string,
  logLevel: process.env.LOG_LEVEL ?? 'info',
  frontendUrl: process.env.FRONTEND_URL ?? 'http://localhost:3002',
});