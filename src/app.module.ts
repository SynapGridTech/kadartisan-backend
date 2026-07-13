import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import config from './config/app.config';
import { envValidationSchema } from './config/validation';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { ResponseTimeInterceptor } from './common/interceptors/response-time.interceptor';
import { HealthModule } from './health/health.module';
import { PrismaModule } from './database/prisma.module';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/user/user.module';
import { NotificationModule } from './modules/notification/notification.module';
import { AdminModule } from './modules/admin/admin.module';
import { BootstrapModule } from './modules/bootstrap/bootstrap.module';
import { ArtisanModule } from './modules/artisan/artisan.module';
import { BookingModule } from './modules/booking/booking.module';
import { AdminDashboardModule } from './modules/admin-dashboard/admin-dashboard.module';
import { AdminAnalyticsModule } from './modules/admin-analytics/admin-analytics.module';
import { AdminUsersModule } from './modules/admin-users/admin-users.module';
import { AdminBadgesModule } from './modules/admin-badges/admin-badges.module';
import { AdminTransactionsModule } from './modules/admin-transactions/admin-transactions.module';
import { AdminJobsModule } from './modules/admin-jobs/admin-jobs.module';
import { AdminComplaintsModule } from './modules/admin-complaints/admin-complaints.module';
import { AdminAppealsModule } from './modules/admin-appeals/admin-appeals.module';
import { AdminSkillsModule } from './modules/admin-skills/admin-skills.module';
import { AdminCommunicationsModule } from './modules/admin-communications/admin-communications.module';
import { AdminSubscriptionsModule } from './modules/admin-subscriptions/admin-subscriptions.module';
import { AdminSettingsModule } from './modules/admin-settings/admin-settings.module';
import { AdminSecurityModule } from './modules/admin-security/admin-security.module';
import { AdminSupportModule } from './modules/admin-support/admin-support.module';
import { PaymentWebhooksModule } from './modules/payment-webhooks/payment-webhooks.module';

const isProd = process.env.NODE_ENV === 'production';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [config],
      envFilePath: [`.env.${process.env.NODE_ENV}`, '.env'].filter(Boolean),
      validationSchema: envValidationSchema,
    }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.LOG_LEVEL || 'info',
        redact: ['req.headers.authorization', 'req.body.password'],
        transport: !isProd
          ? {
              target: 'pino-pretty',
              options: {
                colorize: true,
                singleLine: true,
                translateTime: 'SYS:standard',
              },
            }
          : undefined,
      },
    }),
    PrismaModule,
    HealthModule,
    AuthModule,
    UsersModule,
    NotificationModule,
    AdminModule,
    BootstrapModule,
    ArtisanModule,
    BookingModule,
    AdminDashboardModule,
    AdminAnalyticsModule,
    AdminUsersModule,
    AdminBadgesModule,
    AdminTransactionsModule,
    AdminJobsModule,
    AdminComplaintsModule,
    AdminAppealsModule,
    AdminSkillsModule,
    AdminCommunicationsModule,
    AdminSubscriptionsModule,
    AdminSettingsModule,
    AdminSecurityModule,
    AdminSupportModule,
    PaymentWebhooksModule,
  ],
  providers: [
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
    { provide: APP_INTERCEPTOR, useClass: ResponseTimeInterceptor },
  ],
})
export class AppModule {}
