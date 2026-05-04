import { Injectable, BadRequestException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { CreateServiceRequestDto } from '../dto/create-service-request.dto';

@Injectable()
export class BookingService {
  constructor(private prisma: PrismaService) {}

  // Create a new service requests
  public async createRequest(userId: number, dto: CreateServiceRequestDto) {
    // Check if user exists
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Create service request
    const request = await this.prisma.serviceRequest.create({
      data: {
        userId,
        title: dto.title,
        description: dto.description,
        image: dto.image,
        state: dto.serviceLocation || '',
        skillRequired: dto.skillRequired,
        budget: dto.budget,
        urgency: dto.urgency,
        contactInfo: dto.contactInfo,
      },
      include: {
        user: true,
      },
    });

    return {
      message: 'Service request created successfully',
      request: {
        id: request.id,
        title: request.title,
        description: request.description,
        image: request.image,
        state: request.state,
        lga: request.lga,
        skillRequired: request.skillRequired,
        budget: request.budget,
        urgency: request.urgency,
        status: request.status,
        createdAt: request.createdAt,
        user: {
          id: request.user.id,
          fullName: request.user.fullName,
          phoneNumber: request.user.phoneNumber,
        },
      },
    };
  }

  // Get service requests with optional filters
  public async getRequests(filters?: {
    state?: string;
    skillRequired?: string;
    status?: string;
  }) {
    const where: any = {};

    if (filters?.state) {
      where.state = filters.state;
    }

    if (filters?.skillRequired) {
      where.skillRequired = filters.skillRequired;
    }

    if (filters?.status) {
      where.status = filters.status;
    }

    const requests = await this.prisma.serviceRequest.findMany({
      where,
      include: {
        user: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return {
      count: requests.length,
      requests: requests.map((request) => ({
        id: request.id,
        title: request.title,
        description: request.description,
        image: request.image,
        state: request.state,
        lga: request.lga,
        skillRequired: request.skillRequired,
        budget: request.budget,
        urgency: request.urgency,
        status: request.status,
        createdAt: request.createdAt,
        user: {
          id: request.user.id,
          fullName: request.user.fullName,
          phoneNumber: request.user.phoneNumber,
        },
      })),
    };
  }

  // Search artisans by skill and location
  public async searchArtisans(filters: {
    skill?: string;
    state?: string;
    lga?: string;
  }) {
    const where: any = {
      user: {
        artisanStatus: 'APPROVED',
      },
      skills: {
        some: {},
      },
    };

    if (filters.skill) {
      where.skills = {
        some: {
          skill: {
            name: filters.skill,
          },
        },
      };
    }

    if (filters.state) {
      where.state = filters.state;
    }

    if (filters.lga) {
      where.lga = filters.lga;
    }

    const artisans = await this.prisma.artisanProfile.findMany({
      where,
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            phoneNumber: true,
            email: true,
            role: true,
          },
        },
        skills: {
          include: {
            skill: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return {
      count: artisans.length,
      artisans: artisans.map((artisan) => ({
        id: artisan.id,
        userId: artisan.userId,
        fullName: artisan.user.fullName,
        phoneNumber: artisan.user.phoneNumber,
        email: artisan.user.email,
        state: artisan.state,
        lga: artisan.lga,
        workshopAddress: artisan.workshopAddress,
        skills: artisan.skills.map((s) => s.skill.name),
        createdAt: artisan.createdAt,
      })),
    };
  }

  // Get available service requests for an artisan
  public async getAvailableRequests(artisanUserId: number) {
    // Verify user is an approved artisan
    const artisan = await this.prisma.artisanProfile.findUnique({
      where: { userId: artisanUserId },
      include: {
        skills: {
          include: {
            skill: true,
          },
        },
      },
    });

    if (!artisan) {
      throw new BadRequestException('Artisan profile not found');
    }

    const skillNames = artisan.skills.map((s) => s.skill.name);

    const requests = await this.prisma.serviceRequest.findMany({
      where: {
        status: 'PENDING',
        OR: [
          { skillRequired: { in: skillNames } },
          { state: artisan.state },
        ],
      },
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            phoneNumber: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return {
      count: requests.length,
      requests: requests.map((request) => ({
        id: request.id,
        title: request.title,
        description: request.description,
        image: request.image,
        state: request.state,
        lga: request.lga,
        skillRequired: request.skillRequired,
        budget: request.budget,
        urgency: request.urgency,
        status: request.status,
        createdAt: request.createdAt,
        user: {
          id: request.user.id,
          fullName: request.user.fullName,
          phoneNumber: request.user.phoneNumber,
        },
      })),
    };
  }

  // Accept a service request as an artisan
  public async acceptRequest(artisanUserId: number, requestId: number) {
    // Verify artisan is approved
    const artisanUser = await this.prisma.user.findUnique({
      where: { id: artisanUserId },
    });

    if (!artisanUser || artisanUser.role !== 'ARTISAN') {
      throw new ForbiddenException('Only artisans can accept requests');
    }

    if (artisanUser.artisanStatus !== 'APPROVED') {
      throw new ForbiddenException('Artisan is not approved');
    }

    // Verify request exists and is pending
    const request = await this.prisma.serviceRequest.findUnique({
      where: { id: requestId },
    });

    if (!request) {
      throw new BadRequestException('Service request not found');
    }

    if (request.status !== 'PENDING') {
      throw new BadRequestException(`Request is already ${request.status.toLowerCase()}`);
    }

    // Update request status to MATCHED and assign artisan
    const updated = await this.prisma.serviceRequest.update({
      where: { id: requestId },
      data: {
        status: 'MATCHED',
        artisanId: artisanUserId,
      },
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            phoneNumber: true,
          },
        },
        artisan: {
          select: {
            id: true,
            fullName: true,
            phoneNumber: true,
          },
        },
      },
    });

    return {
      message: 'Service request accepted successfully',
      request: {
        id: updated.id,
        title: updated.title,
        description: updated.description,
        image: updated.image,
        state: updated.state,
        lga: updated.lga,
        skillRequired: updated.skillRequired,
        budget: updated.budget,
        urgency: updated.urgency,
        status: updated.status,
        createdAt: updated.createdAt,
        user: updated.user,
        artisan: updated.artisan,
      },
    };
  }
}
