import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './providers/auth.service';
import { PrismaModule } from 'src/database/prisma.module';
import { ConfigService } from '@nestjs/config';
import { SmsService } from '../notification/providers/sms.service';
import { EmailService } from '../notification/providers/email.service';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    PrismaModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, SmsService, EmailService, JwtStrategy],
})
export class AuthModule {}
