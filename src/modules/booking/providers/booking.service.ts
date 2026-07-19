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

  //________________ Shape a ServiceRequest record for API responses (matches your interface exactly)
  private shapeRequest(request: any) {
    return {
      id: request.id,
      customerId: request.customer.user.id,
      category: request.category,
      description: request.description,
      budget: request.budget,
      location: request.location,
      preferredSkills: request.preferredSkills,
      status: request.status,
      createdAt: request.createdAt.toISOString(),
      updatedAt: request.updatedAt.toISOString(),
      acceptedArtisanId: request.acceptedArtisan?.user?.id || null,
      // Additional fields preserved
      title: request.title,
      image: request.image,
      state: request.state,
      lga: request.lga,
      urgency: request.urgency,
      contactInfo: request.contactInfo,
      customer: request.customer
        ? {
            id: request.customer.id,
            userId: request.customer.user?.id,
            fullName: request.customer.user?.fullName,
            phone: request.customer.user?.phone || request.customer.user?.phoneNumber,
            profilePicture: request.customer.user?.profilePicture,
          }
        : null,
      acceptedArtisan: request.acceptedArtisan
        ? {
            id: request.acceptedArtisan.id,
            userId: request.acceptedArtisan.user?.id,
            fullName: request.acceptedArtisan.user?.fullName,
            phone: request.acceptedArtisan.user?.phone || request.acceptedArtisan.user?.phoneNumber,
            profilePicture: request.acceptedArtisan.profilePicture,
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

    // Parse location for backward compatibility (extract state from location string)
    let state = '';
    if (dto.location) {
      const locationParts = dto.location.split(',');
      if (locationParts.length > 1) {
        state = locationParts[locationParts.length - 1].trim();
      } else {
        state = dto.location;
      }
    }

    const request = await this.prisma.serviceRequest.create({
      data: {
        customerId: customer.id,
        title: dto.title || '',
        description: dto.description || '',
        image: dto.image || '',
        state: state || '',
        location: dto.location || '',
        category: dto.category || '',
        preferredSkills: dto.preferredSkills || [],
        budget: dto.budget || 0,
        urgency: dto.urgency || '',
        contactInfo: dto.contactInfo || '',
      } as any,
      include: {
        customer: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true, phone: true, profilePicture: true },
            },
          },
        },
      } as any,
    });

    return {
      message: 'Service request created successfully',
      request: this.shapeRequest(request),
    };
  }

  //_________________LOGIC to Get service requests with optional filters
  public async getRequests(filters?: {
    state?: string;
    category?: string;
    status?: string;
  }) {
    const where: any = {};

    if (filters?.state) {
      where.state = filters.state;
    }

    if (filters?.category) {
      where.category = filters.category;
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
        acceptedArtisan: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true, phone: true, profilePicture: true },
            },
          },
        },
      } as any,
      orderBy: { createdAt: 'desc' },
    });

    return {
      count: requests.length,
      requests: requests.map((r) => this.shapeRequest(r)),
    };
  }

  //________________LOGIC to Get the current client's own service requests
  public async getMyRequests(
    userId: string,
    query?: { status?: string; page?: number },
  ) {
    const customer = await this.prisma.customerProfile.findUnique({
      where: { userId },
    });

    if (!customer) {
      throw new BadRequestException(
        'Customer profile not found for this account',
      );
    }

    const where: any = { customerId: customer.id };
    if (query?.status) {
      where.status = query.status;
    }

    const page = query?.page && query.page > 0 ? query.page : 1;
    const pageSize = 10;
    const skip = (page - 1) * pageSize;

    const [total, requests] = await this.prisma.$transaction([
      this.prisma.serviceRequest.count({ where }),
      this.prisma.serviceRequest.findMany({
        where,
        include: {
          customer: {
            include: {
              user: {
                select: {
                  id: true,
                  fullName: true,
                  phoneNumber: true,
                  phone: true,
                  profilePicture: true,
                },
              },
            },
          },
          acceptedArtisan: {
            include: {
              user: {
                select: {
                  id: true,
                  fullName: true,
                  phoneNumber: true,
                  phone: true,
                  profilePicture: true,
                },
              },
            },
          },
        } as any,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
      }),
    ]);

    return {
      count: total,
      page,
      pageSize,
      requests: requests.map((r) => this.shapeRequest(r)),
    };
  }
  //________________LOGIC to Get the current artisan's accepted/ongoing/completed jobs
  public async getArtisanJobs(
    artisanUserId: string,
    query?: { status?: string; page?: number },
  ) {
    const artisan = await this.prisma.artisanProfile.findUnique({
      where: { userId: artisanUserId },
    });

    if (!artisan) {
      throw new NotFoundException('Artisan profile not found for this account');
    }

    const where: any = { acceptedArtisanId: artisan.id };
    if (query?.status) {
      where.status = query.status;
    }

    const page = query?.page && query.page > 0 ? query.page : 1;
    const pageSize = 10;
    const skip = (page - 1) * pageSize;

    const [total, requests] = await this.prisma.$transaction([
      this.prisma.serviceRequest.count({ where }),
      this.prisma.serviceRequest.findMany({
        where,
        include: {
          customer: {
            include: {
              user: {
                select: {
                  id: true,
                  fullName: true,
                  phoneNumber: true,
                  phone: true,
                  profilePicture: true,
                },
              },
            },
          },
          acceptedArtisan: {
            include: {
              user: {
                select: {
                  id: true,
                  fullName: true,
                  phoneNumber: true,
                  phone: true,
                  profilePicture: true,
                },
              },
            },
          },
        } as any,
        orderBy: { updatedAt: 'desc' },
        skip,
        take: pageSize,
      }),
    ]);

    return {
      count: total,
      page,
      pageSize,
      requests: requests.map((r) => this.shapeRequest(r)),
    };
  }

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
        status: 'OPEN',
        OR: [
          { category: { in: skillNames } },
          { location: { contains: (artisan as any).state } },
        ],
      } as any,
      include: {
        customer: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true },
            },
          },
        },
      } as any,
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
      !(artisanUser as any).artisanProfile ||
      ((artisanUser as any).artisanProfile.artisanStatus !== 'APPROVED' && (artisanUser as any).artisanProfile.artisanStatus !== 'ACTIVE')
    ) {
      throw new ForbiddenException('Artisan is not approved or active');
    }

    const request = await this.prisma.serviceRequest.findUnique({
      where: { id: requestId },
    });

    if (!request) {
      throw new BadRequestException('Service request not found');
    }

    if ((request as any).status !== 'OPEN') {
      throw new BadRequestException(
        `Request is already ${(request as any).status.toLowerCase()}`,
      );
    }

    const updated = await this.prisma.serviceRequest.update({
      where: { id: requestId },
      data: {
        status: 'ACCEPTED',
        acceptedArtisanId: (artisanUser as any).artisanProfile.id,
      } as any,
      include: {
        customer: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true, phone: true, profilePicture: true },
            },
          },
        },
        acceptedArtisan: {
          include: {
            user: {
              select: { id: true, fullName: true, phoneNumber: true, phone: true, profilePicture: true },
            },
          },
        },
      } as any,
    });

    return {
      message: 'Service request accepted successfully',
      request: this.shapeRequest(updated),
    };
  }
}