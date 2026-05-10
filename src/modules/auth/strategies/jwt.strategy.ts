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
    // User ids are now UUID strings.
    const userId: string = payload.sub;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      console.log('User not found:', userId);
      return null;
    }

    // Banned
    if (user.bannedAt) {
      throw new UnauthorizedException(
        `Account permanently banned. Reason: ${user.banReason || 'Violation of terms'}`,
      );
    }

    // Suspended
    if (user.suspendedUntil && user.suspendedUntil > new Date()) {
      throw new UnauthorizedException(
        `Account suspended until ${user.suspendedUntil.toLocaleString()}. Reason: ${user.suspensionReason || 'Policy violation'}`,
      );
    }

    return {
      id: user.id,
      fullName: user.fullName,
      role: user.role,
      isVerified: user.isVerified,
    };
  }
}
