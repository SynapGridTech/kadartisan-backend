import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class AdminService {
  constructor(private prisma: PrismaService) {}

  public async getPendingArtisans() {
    return this.prisma.user.findMany({
      where: {
        artisanStatus: 'PENDING',
      },
      select: {
        id: true,
        fullName: true,
        email: true,
        phoneNumber: true,
        createdAt: true,
      },
    });
  }

  public async approveArtisan(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || user.artisanStatus !== 'PENDING') {
      throw new BadRequestException('Invalid artisan request');
    }

    return this.prisma.user.update({
      where: { id: userId },
      data: {
        role: 'ARTISAN',
        artisanStatus: 'APPROVED',
        artisanApprovedAt: new Date(),
      },
    });
  }
 
  public async rejectArtisan(userId: number, reason?: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || user.artisanStatus !== 'PENDING') {
      throw new BadRequestException('Invalid artisan request');
    }

    return this.prisma.user.update({
      where: { id: userId },
      data: {
        artisanStatus: 'REJECTED',
        artisanRejectionReason: reason || null,
      },
    });
  }
}
