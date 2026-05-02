import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { CreateServiceRequestDto } from '../dto/create-service-request.dto';

@Injectable()
export class BookingService {
  constructor(private prisma: PrismaService) {}

  // Create a new service request
  async createRequest(userId: number, dto: CreateServiceRequestDto) {
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
        state: dto.state,
        lga: dto.lga,
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
  async getRequests(filters?: {
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

  /**
   * Search artisans by skill and location
   */
  async searchArtisans(filters: {
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
}
