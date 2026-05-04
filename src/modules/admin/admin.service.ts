import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { EmailService } from '../notification/providers/email.service';

@Injectable()
export class AdminService {
  constructor(
    private prisma: PrismaService,
    private emailService: EmailService,
  ) {}

  private readonly userSelect = {
    id: true,
    fullName: true,
    email: true,
    phoneNumber: true,
    role: true,
    isVerified: true,
    artisanStatus: true,
    artisanApprovedAt: true,
    artisanRejectionReason: true,
    createdAt: true,
    artisanProfile: {
      include: {
        skills: {
          include: {
            skill: true,
          },
        },
      },
    },
  };

  public async getAllUsers() {
    return this.prisma.user.findMany({
      select: this.userSelect,
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getArtisans() {
    return this.prisma.user.findMany({
      where: { role: 'ARTISAN' },
      select: this.userSelect,
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getRegularUsers() {
    return this.prisma.user.findMany({
      where: { role: 'USER' },
      select: this.userSelect,
      orderBy: { createdAt: 'desc' },
    });
  }

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
        artisanProfile: {
          include: {
            skills: {
              include: {
                skill: true,
              },
            },
          },
        },
      },
    });
  }

  public async approveArtisan(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        artisanProfile: {
          include: {
            skills: {
              include: {
                skill: true,
              },
            },
          },
        },
      },
    });

    if (!user || user.artisanStatus !== 'PENDING') {
      throw new BadRequestException('Invalid artisan request');
    }

    // Update user role and status
    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        role: 'ARTISAN',
        artisanStatus: 'APPROVED',
        artisanApprovedAt: new Date(),
      },
    });

    // Send approval email
    if (user.email) {
      try {
        await this.emailService.sendArtisanApprovalEmail(
          user.email,
          user.fullName,
        );
      } catch (error) {
        console.error('Failed to send approval email:', error);
        // Don't fail the operation if email fails
      }
    }

    return {
      message: 'Artisan approved successfully',
      user: {
        id: updatedUser.id,
        fullName: updatedUser.fullName,
        email: updatedUser.email,
        phoneNumber: updatedUser.phoneNumber,
        role: updatedUser.role,
        artisanStatus: updatedUser.artisanStatus,
      },
    };
  }
 
  public async rejectArtisan(userId: number, reason?: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || user.artisanStatus !== 'PENDING') {
      throw new BadRequestException('Invalid artisan request');
    }

    // Update user status
    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        artisanStatus: 'REJECTED',
        artisanRejectionReason: reason || null,
      },
    });

    // Send rejection email
    if (user.email) {
      try {
        await this.emailService.sendArtisanRejectionEmail(
          user.email,
          user.fullName,
          reason,
        );
      } catch (error) {
        console.error('Failed to send rejection email:', error);
        // Don't fail the operation if email fails
      }
    }

    return {
      message: 'Artisan rejected successfully',
      user: {
        id: updatedUser.id,
        fullName: updatedUser.fullName,
        email: updatedUser.email,
        phoneNumber: updatedUser.phoneNumber,
        artisanStatus: updatedUser.artisanStatus,
        rejectionReason: updatedUser.artisanRejectionReason,
      },
    };
  }
}
