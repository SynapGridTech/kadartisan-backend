import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { EmailService } from 'src/modules/notification/providers/email.service';
import { CreateArtisanProfileDto } from '../dto/create-artisan-profile.dto';

@Injectable()
export class ArtisanService {
  constructor(
    private prisma: PrismaService,
    private emailService: EmailService,
  ) {}

  //______________ LOGIC to Create artisan profile after user registration
  public async createProfile(userId: number, dto: CreateArtisanProfileDto) {
    // Check if user exists
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user already has an artisan profile
    const existingProfile = await this.prisma.artisanProfile.findUnique({
      where: { userId },
    });

    if (existingProfile) {
      throw new BadRequestException('Artisan profile already exists');
    }

    // Check if all skills exist in database
    const skills = await this.prisma.skill.findMany({
      where: {
        name: {
          in: dto.skills,
        },
      },
    });

    if (skills.length !== dto.skills.length) {
      const foundSkillNames = skills.map((s) => s.name);
      const invalidSkills = dto.skills.filter(
        (s) => !foundSkillNames.includes(s),
      );
      throw new BadRequestException(
        `Invalid skills: ${invalidSkills.join(', ')}`,
      );
    }

    // Create artisan profile with skills
    const profile = await this.prisma.artisanProfile.create({
      data: {
        userId,
        state: dto.state,
        lga: dto.lga,
        workshopAddress: dto.workshopAddress,
        skills: {
          create: skills.map((skill) => ({
            skillId: skill.id,
          })),
        },
      },
      include: {
        skills: {
          include: {
            skill: true,
          },
        },
      },
    });

    return {
      message: 'Artisan profile created successfully. Pending admin approval.',
      profile: {
        id: profile.id,
        state: profile.state,
        lga: profile.lga,
        workshopAddress: profile.workshopAddress,
        skills: profile.skills.map((s) => s.skill.name),
        createdAt: profile.createdAt,
      },
    };
  }

  //_____________ LOGIC to Get all available skills 
  public async getAllSkills() {
    const skills = await this.prisma.skill.findMany({
      orderBy: {
        category: 'asc',
      },
    });

    // Group by category
    const grouped = skills.reduce((acc, skill) => {
      const category = skill.category || 'Other';
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push({
        id: skill.id,
        name: skill.name,
      });
      return acc;
    }, {});

    return { skills: grouped };
  }

 //________________LOGIC to Allow rejected artisan to reapply
  public async reapplyForArtisan(userId: number, dto: CreateArtisanProfileDto) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Only allow reapplication if status is REJECTED
    if (user.artisanStatus !== 'REJECTED') {
      throw new BadRequestException(
        'Only rejected artisans can reapply. Current status: ' +
          (user.artisanStatus || 'Not applied'),
      );
    }

    // Delete old profile if exists (use try-catch to handle case where profile doesn't exist)
    try {
      await this.prisma.artisanProfile.delete({
        where: { userId },
      });
    } catch (error) {
      // Profile doesn't exist, continue anyway
      if (error.code !== 'P2025') {
        throw error;
      }
    }

    // Reset artisan status to PENDING
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        artisanStatus: 'PENDING',
        artisanRejectionReason: null,
      },
    });

    // Create new profile
    return this.createProfile(userId, dto);
  }

  //__________________ LOGIC to Get all approved artisans
  public async getArtisans() {
    const artisans = await this.prisma.user.findMany({
      where: { role: 'ARTISAN' },
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

    return artisans.map((user) => ({
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
            skills: user.artisanProfile.skills.map((s) => s.skill.name),
            createdAt: user.artisanProfile.createdAt,
            updatedAt: user.artisanProfile.updatedAt,
          }
        : null,
    }));
  }

  //__________________LOGIC to Get all pending artisans
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

  //__________________LOGIC to Approve an artisan
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

    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        role: 'ARTISAN',
        artisanStatus: 'APPROVED',
        artisanApprovedAt: new Date(),
      },
    });

    if (user.email) {
      try {
        await this.emailService.sendArtisanApprovalEmail(
          user.email,
          user.fullName,
        );
      } catch (error) {
        console.error('Failed to send approval email:', error);
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

  //__________________LOGIC to Reject an artisan
  public async rejectArtisan(userId: number, reason?: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || user.artisanStatus !== 'PENDING') {
      throw new BadRequestException('Invalid artisan request');
    }

    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        artisanStatus: 'REJECTED',
        artisanRejectionReason: reason || null,
      },
    });

    if (user.email) {
      try {
        await this.emailService.sendArtisanRejectionEmail(
          user.email,
          user.fullName,
          reason,
        );
      } catch (error) {
        console.error('Failed to send rejection email:', error);
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

  //__________________LOGIC to Search artisans by skill and location
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

  //__________________LOGIC to Get artisan profile by ID
  public async getProfileByUserId(userId: number) {
    const profile = await this.prisma.artisanProfile.findUnique({
      where: { userId },
      include: {
        skills: {
          include: {
            skill: true,
          },
        },
      },
    });

    if (!profile) {
      return null;
    }

    return {
      id: profile.id,
      state: profile.state,
      lga: profile.lga,
      workshopAddress: profile.workshopAddress,
      skills: profile.skills.map((s) => s.skill.name),
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt,
    };
  }
}
