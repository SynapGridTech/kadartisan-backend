import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { CreateServiceRequestDto } from '../dto/create-service-request.dto';

@Injectable()
export class BookingService {
  constructor(private prisma: PrismaService) {}

  //________________ Shape a ServiceRequest record for API responses
  private shapeRequest(request: any) {
    return {
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
      customer: request.customer
        ? {
            id: request.customer.id,
            userId: request.customer.user?.id,
            fullName: request.customer.user?.fullName,
            phoneNumber: request.customer.user?.phoneNumber,
          }
        : null,
      artisan: request.artisan
        ? {
            id: request.artisan.id,
            userId: request.artisan.user?.id,
            fullName: request.artisan.user?.fullName,
            phoneNumber: request.artisan.user?.phoneNumber,
          }
        : null,
    };
  }

  //_________________ LOGIC to Create a new service requests (customer)
  public async createRequest(userId: string, dto: CreateServiceRequestDto) {
    const customer = await this.prisma.customerProfile.findUnique({
      where: { userId },
    });

    if (!customer) {
      throw new BadRequestException(
        'Customer profile not found for this account',
      );
    }

    const request = await this.prisma.serviceRequest.create({
      data: {
        customerId: customer.id,
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
        customer: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true },
            },
          },
        },
      },
    });

    return {
      message: 'Service request created successfully',
      request: this.shapeRequest(request),
    };
  }

  //_________________LOGIC to Get service requests with optional filters
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
        customer: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true },
            },
          },
        },
        artisan: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true },
            },
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return {
      count: requests.length,
      requests: requests.map((r) => this.shapeRequest(r)),
    };
  }

  //________________LOGIC to Get available service requests for an artisan
  public async getAvailableRequests(artisanUserId: string) {
    const artisan = await this.prisma.artisanProfile.findUnique({
      where: { userId: artisanUserId },
      include: {
        skills: { include: { skill: true } },
      },
    });

    if (!artisan) {
      throw new NotFoundException('Artisan profile not found');
    }

    if (artisan.artisanStatus !== 'APPROVED') {
      throw new ForbiddenException('Artisan is not approved');
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
        customer: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true },
            },
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return {
      count: requests.length,
      requests: requests.map((r) => this.shapeRequest(r)),
    };
  }

  //_________________ LOGIC to Accept a service request as an artisan
  public async acceptRequest(artisanUserId: string, requestId: string) {
    const artisanUser = await this.prisma.user.findUnique({
      where: { id: artisanUserId },
      include: { artisanProfile: true },
    });

    if (!artisanUser || artisanUser.role !== 'ARTISAN') {
      throw new ForbiddenException('Only artisans can accept requests');
    }

    if (
      !artisanUser.artisanProfile ||
      artisanUser.artisanProfile.artisanStatus !== 'APPROVED'
    ) {
      throw new ForbiddenException('Artisan is not approved');
    }

    const request = await this.prisma.serviceRequest.findUnique({
      where: { id: requestId },
    });

    if (!request) {
      throw new BadRequestException('Service request not found');
    }

    if (request.status !== 'PENDING') {
      throw new BadRequestException(
        `Request is already ${request.status.toLowerCase()}`,
      );
    }

    const updated = await this.prisma.serviceRequest.update({
      where: { id: requestId },
      data: {
        status: 'MATCHED',
        artisanId: artisanUser.artisanProfile.id,
      },
      include: {
        customer: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true },
            },
          },
        },
        artisan: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true },
            },
          },
        },
      },
    });

    return {
      message: 'Service request accepted successfully',
      request: this.shapeRequest(updated),
    };
  }
}
