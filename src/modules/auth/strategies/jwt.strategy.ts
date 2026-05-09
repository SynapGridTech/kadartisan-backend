import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  public async validate(payload: any) {
    // IMPORTANT: your Prisma id is Int
    const userId = Number(payload.sub);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      console.log('❌ User not found:', userId);
      return null;
    }

    // 🚨 CHECK IF BANNED
    if (user.bannedAt) {
      throw new UnauthorizedException(
        `Account permanently banned. Reason: ${user.banReason || 'Violation of terms'}`,
      );
    }

    // 🚨 CHECK IF SUSPENDED
    if (user.suspendedUntil && user.suspendedUntil > new Date()) {
      throw new UnauthorizedException(
        `Account suspended until ${user.suspendedUntil.toLocaleString()}. Reason: ${user.suspensionReason || 'Policy violation'}`,
      );
    }
    // Whatever you return becomes req.user
    return {
      id: payload.sub,
      fullName: user.fullName,
      role: user.role,
      isVerified: user.isVerified,
    };
  }
}
