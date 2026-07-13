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

  //_______________Logic to shape a user record into a role-aware public response
  private shapeUser(user: any) {
    const base = {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      role: user.role,
      isVerified: user.isVerified,
      createdAt: user.createdAt,
    };

    // Only artisans expose an artisanProfile block.
    if (user.role === 'ARTISAN' && user.artisanProfile) {
      return {
        ...base,
        artisanProfile: {
          id: user.artisanProfile.id,
          state: user.artisanProfile.state,
          lga: user.artisanProfile.lga,
          workshopAddress: user.artisanProfile.workshopAddress,
          artisanStatus: user.artisanProfile.artisanStatus,
          artisanApprovedAt: user.artisanProfile.artisanApprovedAt,
          artisanRejectionReason: user.artisanProfile.artisanRejectionReason,
          skills:
            user.artisanProfile.skills?.map((s: any) => s.skill.name) ?? [],
          createdAt: user.artisanProfile.createdAt,
          updatedAt: user.artisanProfile.updatedAt,
        },
      };
    }

    // USER and ADMIN responses stay lean — no artisan/customer fields.
    return base;
  }

  //_______________Logic to Get ALL users (customers & artisans)
  public async getAllUsers() {
    const users = await this.prisma.user.findMany({
      where: {
        role: { not: 'ADMIN' },
      },
      include: {
        artisanProfile: {
          include: {
            skills: { include: { skill: true } },
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return users.map((user) => this.shapeUser(user));
  }

  //_______________Logic to Get ALL regular users (non-artisans)
  public async getRegularUsers() {
    const users = await this.prisma.user.findMany({
      where: { role: 'USER' },
      include: {
        artisanProfile: {
          include: {
            skills: { include: { skill: true } },
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return users.map((user) => this.shapeUser(user));
  }

  //_______________Logic to Get current authenticated user profile
  public async getProfileById(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        artisanProfile: {
          include: {
            skills: { include: { skill: true } },
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.shapeUser(user);
  }

  //_______________ Logic to fetch a USER by ID
  public async getUserById(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        artisanProfile: {
          include: {
            skills: { include: { skill: true } },
            acceptedRequests: { orderBy: { createdAt: 'desc' } },
          },
        },
        customerProfile: {
          include: {
            serviceRequests: { orderBy: { createdAt: 'desc' } },
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const base: any = this.shapeUser(user);

    // Only attach the relational collections relevant to the caller's role.
    if (user.role === 'USER') {
      base.bookings = user.customerProfile?.serviceRequests ?? [];
    }
    if (user.role === 'ARTISAN') {
      base.acceptedJobs = user.artisanProfile?.acceptedRequests ?? [];
    }

    return base;
  }

  //______________ Logic to get a User's STAT
  public async getUserStats(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        customerProfile: {
          include: {
            serviceRequests: true,
          },
        },
        artisanProfile: {
          include: {
            acceptedRequests: true,
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const countByStatus = (requests: any[], status: string) =>
      requests.filter((r) => r.status === status).length;

    const result: any = {
      userId: user.id,
      role: user.role,
    };

    // Only customers see request stats.
    if (user.role === 'USER') {
      const serviceRequests = user.customerProfile?.serviceRequests ?? [];
      result.requests = {
        total: serviceRequests.length,
        open: countByStatus(serviceRequests, 'OPEN'),
        accepted: countByStatus(serviceRequests, 'ACCEPTED'),
        inProgress: countByStatus(serviceRequests, 'IN_PROGRESS'),
        completed: countByStatus(serviceRequests, 'COMPLETED'),
        cancelled: countByStatus(serviceRequests, 'CANCELLED'),
      };
    }

    // Only artisans see job stats.
    if (user.role === 'ARTISAN') {
      const acceptedRequests = user.artisanProfile?.acceptedRequests ?? [];
      result.jobs = {
        total: acceptedRequests.length,
        accepted: countByStatus(acceptedRequests, 'ACCEPTED'),
        inProgress: countByStatus(acceptedRequests, 'IN_PROGRESS'),
        completed: countByStatus(acceptedRequests, 'COMPLETED'),
        cancelled: countByStatus(acceptedRequests, 'CANCELLED'),
      };
    }

    return result;
  }
}
