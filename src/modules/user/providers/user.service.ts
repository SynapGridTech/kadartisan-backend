import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { UpdateUserDto } from '../dto/update-user.dto';

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

    // Customers expose their saved location/address block when present.
    if (user.role === 'USER' && user.customerProfile) {
      return {
        ...base,
        profilePicture: user.profilePicture,
        location: user.customerProfile.location,
        state: user.customerProfile.state,
        lga: user.customerProfile.lga,
        address: user.customerProfile.address,
      };
    }

    // USER and ADMIN responses stay lean — no artisan/customer fields.
    return base;
  }

  //_______________ Logic to update the current user's profile + customer address
  public async updateProfile(userId: string, dto: UpdateUserDto) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Guard the unique email constraint with a friendly error.
    if (dto.email && dto.email !== user.email) {
      const existing = await this.prisma.user.findUnique({
        where: { email: dto.email },
      });
      if (existing && existing.id !== userId) {
        throw new ConflictException('Email is already in use');
      }
    }

    const userData: any = {};
    if (dto.fullName !== undefined) userData.fullName = dto.fullName;
    if (dto.email !== undefined) userData.email = dto.email;
    if (dto.profilePicture !== undefined)
      userData.profilePicture = dto.profilePicture;

    const addressData: any = {};
    if (dto.location !== undefined) addressData.location = dto.location;
    if (dto.state !== undefined) addressData.state = dto.state;
    if (dto.lga !== undefined) addressData.lga = dto.lga;
    if (dto.address !== undefined) addressData.address = dto.address;

    await this.prisma.$transaction(async (tx) => {
      if (Object.keys(userData).length > 0) {
        await tx.user.update({ where: { id: userId }, data: userData });
      }

      // Persist address on the CustomerProfile every account has.
      if (Object.keys(addressData).length > 0) {
        await tx.customerProfile.update({
          where: { userId },
          data: addressData,
        });
      }
    });

    return this.getProfileById(userId);
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
        customerProfile: true,
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
