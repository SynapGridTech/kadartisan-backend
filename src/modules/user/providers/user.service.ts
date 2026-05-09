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

  public async create(data: any) {
    return this.prisma.user.create({
      data,
    });
  }

  //Logic to Get SELF ID 
  public async getAllUsers() {
    return this.prisma.user.findMany({
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
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getRegularUsers() {
    return this.prisma.user.findMany({
      where: { role: 'USER' },
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
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getProfileById(userId: number) {
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

  // Logic to fetch a USER by ID 
  public async getUserById(userId: number) {
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
        serviceRequests: {
          orderBy: { createdAt: 'desc' },
        },
        acceptedRequests: {
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

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
      createdAt: user.createdAt,
      artisanProfile: user.artisanProfile
        ? {
            id: user.artisanProfile.id,
            state: user.artisanProfile.state,
            lga: user.artisanProfile.lga,
            workshopAddress: user.artisanProfile.workshopAddress,
            skills: user.artisanProfile.skills.map((s) => ({
              id: s.skill.id,
              name: s.skill.name,
              category: s.skill.category,
            })),
            createdAt: user.artisanProfile.createdAt,
            updatedAt: user.artisanProfile.updatedAt,
          }
        : null,
      bookings: user.serviceRequests,
      acceptedJobs: user.acceptedRequests,
    };
  }

  // Logic to get a User's STAT
  public async getUserStats(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        serviceRequests: true,
        acceptedRequests: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const countByStatus = (requests: any[], status: string) =>
      requests.filter((r) => r.status === status).length;

    return {
      userId: user.id,
      role: user.role,
      // Customer stats (requests made)
      requests: {
        total: user.serviceRequests.length,
        pending: countByStatus(user.serviceRequests, 'PENDING'),
        matched: countByStatus(user.serviceRequests, 'MATCHED'),
        inProgress: countByStatus(user.serviceRequests, 'IN_PROGRESS'),
        completed: countByStatus(user.serviceRequests, 'COMPLETED'),
        cancelled: countByStatus(user.serviceRequests, 'CANCELLED'),
      },
      // Artisan stats (jobs accepted)
      jobs: {
        total: user.acceptedRequests.length,
        pending: countByStatus(user.acceptedRequests, 'MATCHED'),
        inProgress: countByStatus(user.acceptedRequests, 'IN_PROGRESS'),
        completed: countByStatus(user.acceptedRequests, 'COMPLETED'),
        cancelled: countByStatus(user.acceptedRequests, 'CANCELLED'),
      },
    };
  }
}
