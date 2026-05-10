import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { EmailService } from 'src/modules/notification/providers/email.service';
import { CreateArtisanProfileDto } from '../dto/create-artisan-profile.dto';

@Injectable()
export class ArtisanService {
  constructor(
    private prisma: PrismaService,
    private emailService: EmailService,
  ) {}

  //______________ LOGIC to Create/populate an artisan profile after user registration
  public async createProfile(userId: string, dto: CreateArtisanProfileDto) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Validate all skills exist
    const skills = await this.prisma.skill.findMany({
      where: { name: { in: dto.skills } },
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

    const existing = await this.prisma.artisanProfile.findUnique({
      where: { userId },
    });

    // Block re-submission once approved or rejected
    if (existing && existing.artisanStatus === 'APPROVED') {
      throw new BadRequestException('Artisan profile already approved');
    }
    if (existing && existing.artisanStatus === 'REJECTED') {
      throw new BadRequestException(
        'Your previous application was rejected. Please use the reapply endpoint.',
      );
    }

    // If an empty PENDING profile already exists (created during registration),
    // populate it. Otherwise create it fresh.
    const profile = existing
      ? await this.prisma.artisanProfile.update({
          where: { userId },
          data: {
            state: dto.state,
            lga: dto.lga,
            workshopAddress: dto.workshopAddress,
            skills: {
              deleteMany: {},
              create: skills.map((skill) => ({ skillId: skill.id })),
            },
          },
          include: {
            skills: { include: { skill: true } },
          },
        })
      : await this.prisma.artisanProfile.create({
          data: {
            userId,
            state: dto.state,
            lga: dto.lga,
            workshopAddress: dto.workshopAddress,
            skills: {
              create: skills.map((skill) => ({ skillId: skill.id })),
            },
          },
          include: {
            skills: { include: { skill: true } },
          },
        });

    return {
      message: 'Artisan profile created successfully. Pending admin approval.',
      profile: {
        id: profile.id,
        state: profile.state,
        lga: profile.lga,
        workshopAddress: profile.workshopAddress,
        artisanStatus: profile.artisanStatus,
        skills: profile.skills.map((s) => s.skill.name),
        createdAt: profile.createdAt,
      },
    };
  }

  //_____________ LOGIC to Get all available skills
  public async getAllSkills() {
    const skills = await this.prisma.skill.findMany({
      orderBy: { category: 'asc' },
    });

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
  public async reapplyForArtisan(
    userId: string,
    dto: CreateArtisanProfileDto,
  ) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const artisanProfile = await this.prisma.artisanProfile.findUnique({
      where: { userId },
    });

    if (!artisanProfile || artisanProfile.artisanStatus !== 'REJECTED') {
      throw new BadRequestException(
        'Only rejected artisans can reapply. Current status: ' +
          (artisanProfile?.artisanStatus || 'Not applied'),
      );
    }

    // Reset to PENDING and clear skills; createProfile below will repopulate
    await this.prisma.artisanProfile.update({
      where: { userId },
      data: {
        artisanStatus: 'PENDING',
        artisanRejectionReason: null,
        skills: { deleteMany: {} },
      },
    });

    return this.createProfile(userId, dto);
  }

  //__________________ LOGIC to Get all approved artisans
  public async getArtisans() {
    const artisans = await this.prisma.user.findMany({
      where: {
        role: 'ARTISAN',
        artisanProfile: {
          artisanStatus: 'APPROVED',
        },
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

    return artisans.map((user) => ({
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      role: user.role,
      isVerified: user.isVerified,
      createdAt: user.createdAt,
      artisanProfile: user.artisanProfile
        ? {
            id: user.artisanProfile.id,
            state: user.artisanProfile.state,
            lga: user.artisanProfile.lga,
            workshopAddress: user.artisanProfile.workshopAddress,
            artisanStatus: user.artisanProfile.artisanStatus,
            artisanApprovedAt: user.artisanProfile.artisanApprovedAt,
            artisanRejectionReason: user.artisanProfile.artisanRejectionReason,
            skills: user.artisanProfile.skills.map((s) => s.skill.name),
            createdAt: user.artisanProfile.createdAt,
            updatedAt: user.artisanProfile.updatedAt,
          }
        : null,
    }));
  }

  //__________________LOGIC to Get all pending artisans
  public async getPendingArtisans() {
    const profiles = await this.prisma.artisanProfile.findMany({
      where: { artisanStatus: 'PENDING' },
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            email: true,
            phoneNumber: true,
            createdAt: true,
          },
        },
        skills: { include: { skill: true } },
      },
      orderBy: { createdAt: 'desc' },
    });

    return profiles.map((profile) => ({
      userId: profile.user.id,
      fullName: profile.user.fullName,
      email: profile.user.email,
      phoneNumber: profile.user.phoneNumber,
      createdAt: profile.user.createdAt,
      artisanProfile: {
        id: profile.id,
        state: profile.state,
        lga: profile.lga,
        workshopAddress: profile.workshopAddress,
        artisanStatus: profile.artisanStatus,
        skills: profile.skills.map((s) => s.skill.name),
      },
    }));
  }

  //__________________LOGIC to Approve an artisan
  public async approveArtisan(userId: string) {
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

    if (
      !user ||
      !user.artisanProfile ||
      user.artisanProfile.artisanStatus !== 'PENDING'
    ) {
      throw new BadRequestException('Invalid artisan request');
    }

    const [updatedUser, updatedProfile] = await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: userId },
        data: { role: 'ARTISAN' },
      }),
      this.prisma.artisanProfile.update({
        where: { userId },
        data: {
          artisanStatus: 'APPROVED',
          artisanApprovedAt: new Date(),
        },
      }),
    ]);

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
        artisanStatus: updatedProfile.artisanStatus,
      },
    };
  }

  //__________________LOGIC to Reject an artisan
  public async rejectArtisan(userId: string, reason?: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { artisanProfile: true },
    });

    if (
      !user ||
      !user.artisanProfile ||
      user.artisanProfile.artisanStatus !== 'PENDING'
    ) {
      throw new BadRequestException('Invalid artisan request');
    }

    const updatedProfile = await this.prisma.artisanProfile.update({
      where: { userId },
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
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phoneNumber: user.phoneNumber,
        artisanStatus: updatedProfile.artisanStatus,
        rejectionReason: updatedProfile.artisanRejectionReason,
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
      artisanStatus: 'APPROVED',
      skills: {
        some: {},
      },
    };

    if (filters.skill) {
      where.skills = {
        some: {
          skill: { name: filters.skill },
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
        skills: { include: { skill: true } },
      },
      orderBy: { createdAt: 'desc' },
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

  //__________________LOGIC to Get artisan profile by user ID
  public async getProfileByUserId(userId: string) {
    const profile = await this.prisma.artisanProfile.findUnique({
      where: { userId },
      include: {
        skills: { include: { skill: true } },
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
      artisanStatus: profile.artisanStatus,
      artisanApprovedAt: profile.artisanApprovedAt,
      artisanRejectionReason: profile.artisanRejectionReason,
      skills: profile.skills.map((s) => s.skill.name),
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt,
    };
  }
}
