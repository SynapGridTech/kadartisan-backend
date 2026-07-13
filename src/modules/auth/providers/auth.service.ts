import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/database/prisma.service';
import { LoginResponseDto } from '../dto/login-response.dto';
import { OtpChannel } from '@prisma/client';
import { SmsService } from 'src/modules/notification/providers/sms.service';
import { EmailService } from 'src/modules/notification/providers/email.service';
import { ResetPasswordDto } from '../dto/reset-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private smsService: SmsService,
    private emailService: EmailService,
  ) {}

  //----------------------------------------
  // OTP: request & verify
  //----------------------------------------
  public async requestOtp(
    identifier: string,
    channel: OtpChannel,
    role?: 'USER' | 'ARTISAN',
  ) {
    const selectedRole = role === 'ARTISAN' ? 'ARTISAN' : 'USER';

    await this.prisma.otp.findFirst({
      where: {
        identifier,
        channel,
        createdAt: { gte: new Date(Date.now() - 30 * 1000) },
      },
    });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);

    await this.prisma.otp.create({
      data: {
        identifier,
        channel,
        code: hashedOtp,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      },
    });

    if (channel === OtpChannel.PHONE) {
      console.log('OTP generated:', otp);
    }
    if (channel === OtpChannel.EMAIL) {
      console.log(`OTP for ${identifier}: ${otp}`);
    }

    return {
      message: 'OTP sent successfully',
      role: selectedRole,
      otp, // TODO: remove in production
    };
  }

  public async verifyOtp(
    identifier: string,
    otp: string,
    channel: OtpChannel,
    role?: 'USER' | 'ARTISAN',
  ) {
    const selectedRole = role === 'ARTISAN' ? 'ARTISAN' : 'USER';

    const record = await this.prisma.otp.findFirst({
      where: {
        identifier,
        channel,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!record) {
      throw new BadRequestException('No active OTP found. Please request a new OTP first.');
    }

    const match = await bcrypt.compare(otp, record.code);
    if (!match) {
      throw new BadRequestException('Incorrect OTP code. Please check and try again.');
    }

    await this.prisma.otp.update({
      where: { id: record.id },
      data: { isUsed: true },
    });

    const tempToken = await this.jwtService.signAsync(
      { identifier, channel, role: selectedRole },
      { secret: process.env.JWT_TEMP_SECRET, expiresIn: '10m' },
    );

    return { tempToken };
  }

  //----------------------------------------
  // Registration: creates User + CustomerProfile,
  // and ArtisanProfile (PENDING) when role = ARTISAN.
  //----------------------------------------
  public async completeRegistration(dto: any) {
    if (dto.password !== dto.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const payload = this.jwtService.verify(dto.tempToken, {
      secret: process.env.JWT_TEMP_SECRET,
    });

    const { identifier, channel, role } = payload;

    let email: string | undefined;
    let phoneNumber: string;

    if (channel === 'EMAIL') {
      // Use email from token to prevent tampering, but if dto.email is provided and matches, use it
      // This ensures the email in the user record matches what was verified via OTP
      email = identifier;
      phoneNumber = dto.phoneNumber || dto.phone; // Support both phoneNumber and phone fields from request
    } else {
      phoneNumber = identifier;
      email = dto.email; // If channel is phone, use email from request if provided
    }

    const orConditions: any[] = [{ phoneNumber }];
    if (email) orConditions.push({ email });

    const existing = await this.prisma.user.findFirst({
      where: { OR: orConditions },
    });
    if (existing) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const isArtisanRequest = role === 'ARTISAN';

    const user = await this.prisma.$transaction(async (tx) => {
      const createdUser = await tx.user.create({
        data: {
          fullName: dto.fullName,
          phoneNumber,
          phone: phoneNumber, // Keep phone field in sync with phoneNumber
          email,
          password: hashedPassword,
          profilePicture: dto.profilePicture, // Save profilePicture from request
          // Artisan applicants get the ARTISAN role immediately so they can
          // submit their profile; approval only flips artisanStatus.
          role: isArtisanRequest ? 'ARTISAN' : 'USER',
          isVerified: true,
        },
      });

      // Every account gets a CustomerProfile so they can request services.
      await tx.customerProfile.create({
        data: { userId: createdUser.id },
      });

      // Artisan applicants also get an ArtisanProfile placeholder with PENDING status.
      // Note: createProfile endpoint is expected to populate state/lga/skills afterwards.
      if (isArtisanRequest) {
        await tx.artisanProfile.create({
          data: {
            userId: createdUser.id,
            state: '',
            artisanStatus: 'PENDING',
          },
        });
      }

      return createdUser;
    });

    return {
      accessToken: await this.jwtService.signAsync(
        { sub: user.id, role: user.role },
        { secret: process.env.JWT_SECRET, expiresIn: '15m' },
      ),
      message: isArtisanRequest
        ? 'Registration successful. Artisan request pending admin approval.'
        : 'Registration successful.',
    };
  }

  //----------------------------------------
  // Login
  //----------------------------------------
  public async login(
    identifier: string,
    password: string,
    channel: OtpChannel,
  ): Promise<LoginResponseDto> {
    let user;

    // Use findFirst with OR condition to handle both email and phone number queries more robustly
    if (channel === OtpChannel.EMAIL) {
      user = await this.prisma.user.findFirst({
        where: { email: identifier },
      });
    } else if (channel === OtpChannel.PHONE) {
      user = await this.prisma.user.findFirst({
        where: { phoneNumber: identifier },
      });
    }

    if (!user) {
      console.log(`Login failed: No user found with identifier ${identifier} and channel ${channel}`);
      throw new UnauthorizedException('No account found with the provided email/phone number. Please check your login details or register first.');
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
      throw new UnauthorizedException(
        `Account locked. Try again after ${user.lockUntil.toLocaleTimeString()}`,
      );
    }

    if (user.bannedAt) {
      throw new UnauthorizedException(
        `Account permanently banned. Reason: ${user.banReason || 'Violation of terms'}`,
      );
    }

    if (user.suspendedUntil && user.suspendedUntil > new Date()) {
      throw new UnauthorizedException(
        `Account suspended until ${user.suspendedUntil.toLocaleString()}. Reason: ${user.suspensionReason || 'Policy violation'}`,
      );
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      const attempts = user.failedLoginAttempts + 1;
      if (attempts >= 3) {
        const lockUntil = new Date(Date.now() + 15 * 60 * 1000);
        await this.prisma.user.update({
          where: { id: user.id },
          data: { failedLoginAttempts: 0, lockUntil },
        });
        if (user.email) {
          await this.emailService.sendSecurityAlertEmail(
            user.email,
            user.fullName,
            lockUntil,
          );
        }
      } else {
        await this.prisma.user.update({
          where: { id: user.id },
          data: { failedLoginAttempts: attempts },
        });
      }
      throw new UnauthorizedException('Incorrect password. Please check your password and try again.');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockUntil: null },
    });

    const accessToken = await this.jwtService.signAsync(
      {
        sub: user.id,
        isVerified: user.isVerified,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        role: user.role,
      },
      { secret: process.env.JWT_SECRET, expiresIn: '15m' },
    );

    const refreshToken = await this.jwtService.signAsync(
      { sub: user.id },
      { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
    );

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: hashedRefreshToken },
    });

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        role: user.role,
        isVerified: user.isVerified,
      },
    };
  }

  //----------------------------------------
  // Refresh / logout
  //----------------------------------------
  public async refresh(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access denied');
    }

    const isMatch = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!isMatch) {
      throw new ForbiddenException('Invalid refresh token');
    }

    const newAccessToken = await this.jwtService.signAsync(
      { sub: user.id },
      { secret: process.env.JWT_SECRET, expiresIn: '15m' },
    );

    return { accessToken: newAccessToken };
  }

  public async verifyRefreshToken(token: string) {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  public async logout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
    return { message: 'User logged out successfully' };
  }

  //----------------------------------------
  // Password reset
  //----------------------------------------
  public async requestPasswordReset(identifier: string, channel: OtpChannel) {
    let user;
    if (channel === 'EMAIL') {
      user = await this.prisma.user.findUnique({
        where: { email: identifier },
      });
    } else {
      user = await this.prisma.user.findUnique({
        where: { phoneNumber: identifier },
      });
    }

    if (!user) {
      return { message: 'If an account exists, an OTP has been sent.' };
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);

    await this.prisma.otp.create({
      data: {
        identifier: channel === 'EMAIL' ? user.email! : user.phoneNumber,
        channel,
        code: hashedOtp,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      },
    });

    if (channel === 'EMAIL') {
      console.log(`OTP for ${user.email}: ${otp}`);
    } else {
      console.log(`OTP for ${user.phoneNumber}: ${otp}`);
    }

    return {
      message: 'If an account exists, an OTP has been sent.',
      otp, // TODO: remove in production
    };
  }

  public async verifyResetOtp(
    identifier: string,
    otp: string,
    channel: OtpChannel,
  ) {
    const record = await this.prisma.otp.findFirst({
      where: {
        identifier,
        channel,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!record) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    const match = await bcrypt.compare(otp, record.code);
    if (!match) {
      throw new BadRequestException('Invalid OTP');
    }

    await this.prisma.otp.update({
      where: { id: record.id },
      data: { isUsed: true },
    });

    const resetToken = await this.jwtService.signAsync(
      { identifier, channel, type: 'PASSWORD_RESET' },
      { secret: process.env.JWT_TEMP_SECRET, expiresIn: '10m' },
    );

    return { resetToken };
  }

  public async resetPassword(dto: ResetPasswordDto) {
    if (dto.newPassword !== dto.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const payload = this.jwtService.verify(dto.tempToken, {
      secret: process.env.JWT_TEMP_SECRET,
    });

    if (payload.type !== 'PASSWORD_RESET') {
      throw new UnauthorizedException('Invalid token');
    }

    const identifier = payload.identifier;

    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: identifier }, { phoneNumber: identifier }],
      },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    const hashedPassword = await bcrypt.hash(dto.newPassword, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        refreshToken: null,
      },
    });

    return { message: 'Password reset successful' };
  }

  //----------------------------------------
  // Public appeal submission
  //----------------------------------------
  public async submitAppeal(identifier: string, reason: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ phoneNumber: identifier }, { email: identifier }],
      },
    });

    if (!user) {
      throw new BadRequestException('No account found with this identifier');
    }

    if (!user.suspendedUntil && !user.bannedAt) {
      throw new BadRequestException('Your account is not suspended or banned');
    }

    const existingAppeal = await this.prisma.appeal.findUnique({
      where: { userId: user.id },
    });

    if (existingAppeal) {
      if (existingAppeal.status === 'PENDING') {
        throw new BadRequestException(
          'You already have a pending appeal. Please wait for admin review.',
        );
      }
      await this.prisma.appeal.delete({
        where: { id: existingAppeal.id },
      });
    }

    const appeal = await this.prisma.appeal.create({
      data: {
        userId: user.id,
        reason,
      },
    });

    return {
      message: 'Appeal submitted successfully. Admin will review it shortly.',
      appealId: appeal.id,
    };
  }
}