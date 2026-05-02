import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  public findByPhone(phoneNumber: string) {
    return this.prisma.user.findUnique({
      where: { phoneNumber },
    });
  }

  async create(data: any) {
    return this.prisma.user.create({
      data,
    });
  }

  async getProfileById(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
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
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Transform the response
    return {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      role: user.role,
      isVerified: user.isVerified,
      artisanStatus: user.artisanStatus,
      artisanApprovedAt: user.artisanApprovedAt,
      artisanRejectionReason: user.artisanRejectionReason,
      artisanProfile: user.artisanProfile
        ? {
            id: user.artisanProfile.id,
            state: user.artisanProfile.state,
            lga: user.artisanProfile.lga,
            workshopAddress: user.artisanProfile.workshopAddress,
            skills: user.artisanProfile.skills.map((s) => s.skill.name),
            createdAt: user.artisanProfile.createdAt,
            updatedAt: user.artisanProfile.updatedAt,
          }
        : null,
      createdAt: user.createdAt,
    };
  }
}
