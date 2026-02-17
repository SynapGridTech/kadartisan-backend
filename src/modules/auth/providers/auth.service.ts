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

  //_______________Logic for OTP generation, verification, and user registration/login
  public async requestOtp(identifier: string, channel: OtpChannel) {
    const lastOtp = await this.prisma.otp.findFirst({
      where: {
        identifier,
        channel,
        createdAt: {
          gte: new Date(Date.now() - 30 * 1000),
        },
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

    //  Send OTP based on selected channel
    if (channel === OtpChannel.PHONE) {
      // await this.smsService.sendSms(
      //   identifier,
      //   `Your OTP is ${otp}. It expires in 5 minutes.`,
      // );
      console.log('OTP generated:', otp);
    }

    if (channel === OtpChannel.EMAIL) {
      await this.emailService.sendOtpEmail(identifier, otp);
    }

    return { message: 'OTP sent successfully' };
  }

  //______________ Verify OTP and return a temporary token for registration _________
  public async verifyOtp(identifier: string, otp: string, channel: OtpChannel) {
    const record = await this.prisma.otp.findFirst({
      where: {
        identifier,
        channel,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: {
        createdAt: 'desc',
      },
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

    const tempToken = await this.jwtService.signAsync(
      { identifier, channel },
      {
        secret: process.env.JWT_TEMP_SECRET,
        expiresIn: '10m',
      },
    );

    return { tempToken };
  }

  //____________ Complete registration using temp token and user details
  public async completeRegistration(dto: any) {
    if (dto.password !== dto.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const payload = this.jwtService.verify(dto.tempToken, {
      secret: process.env.JWT_TEMP_SECRET,
    });

    const { identifier, channel } = payload;

    let email: string | undefined;
    let phoneNumber: string;

    if (channel === 'EMAIL') {
      email = identifier;
      phoneNumber = dto.phoneNumber;
    } else {
      phoneNumber = identifier;
    }

    const orConditions: any[] = [{ phoneNumber }];

    if (email) {
      orConditions.push({ email });
    }

    const existing = await this.prisma.user.findFirst({
      where: {
        OR: orConditions,
      },
    });

    if (existing) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        fullName: dto.fullName,
        phoneNumber,
        email,
        password: hashedPassword,
        role: dto.role || 'USER',
        isVerified: true,
      },
    });

    return {
      accessToken: await this.jwtService.signAsync(
        { sub: user.id },
        {
          secret: process.env.JWT_SECRET,
          expiresIn: '15m',
        },
      ),
    };
  }

  //____________ Logic for User login ________________
  public async login(
    // phoneNumber: string,
    identifier: string,
    password: string,
    channel: OtpChannel,
  ): Promise<LoginResponseDto> {
    let user;

    if (channel === OtpChannel.EMAIL) {
      user = await this.prisma.user.findUnique({
        where: { email: identifier },
      });
    }

    if (channel === OtpChannel.PHONE) {
      user = await this.prisma.user.findUnique({
        where: { phoneNumber: identifier },
      });
    }

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // 🔐 Generate Access Token
    const accessToken = await this.jwtService.signAsync(
      {
        sub: user.id,
        isVerified: user.isVerified,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        role: user.role,
      },
      {
        secret: process.env.JWT_SECRET,
        expiresIn: '15m',
      },
    );

    // 🔐 Generate Refresh Token
    const refreshToken = await this.jwtService.signAsync(
      { sub: user.id },
      {
        secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      },
    );

    // 🔐 Hash refresh token before saving
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: hashedRefreshToken },
    });

    return {
      accessToken,
      refreshToken, // return to client
      user: {
        id: user.id,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        role: user.role,
        isVerified: user.isVerified,
      },
    };
  }

  //____________ Logic for refreshing access token using refresh token ________________
  public async refresh(userId: number, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access denied');
    }

    const isMatch = await bcrypt.compare(refreshToken, user.refreshToken);

    if (!isMatch) {
      throw new ForbiddenException('Invalid refresh token');
    }

    const newAccessToken = await this.jwtService.signAsync(
      { sub: user.id },
      {
        secret: process.env.JWT_SECRET,
        expiresIn: '15m',
      },
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

  //____________Logic for User logout ________________
  public async logout(userId: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    return { message: 'User logged out successfully' };
  }

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

    // Prevent user enumeration
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

    // 🔥 SEND OTP HERE
    if (channel === 'EMAIL') {
      // call your email service
      await this.emailService.sendOtpEmail(user.email!, otp);
      console.log(`OTP for ${user.email}: ${otp}`);
    } else {
      // call your SMS service
      console.log(`OTP for ${user.phoneNumber}: ${otp}`);
    }

    return { message: 'If an account exists, an OTP has been sent.' };
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
      {
        secret: process.env.JWT_TEMP_SECRET,
        expiresIn: '10m',
      },
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
        refreshToken: null, // force logout everywhere
      },
    });

    return { message: 'Password reset successful' };
  }
}
