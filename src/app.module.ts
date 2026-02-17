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
  ],
  providers: [
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  { provide: APP_INTERCEPTOR, useClass: ResponseTimeInterceptor },

  ],
})
export class AppModule {}