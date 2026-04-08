import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { CreateArtisanProfileDto } from '../dto/create-artisan-profile.dto';

@Injectable()
export class ArtisanService {
  constructor(
    private prisma: PrismaService,
  ) {}

  // Create artisan profile after user registration
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

  // Get all available skills (for frontend dropdown)
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

 //________________ Allow rejected artisan to reapply
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

  //__________________ Get artisan profile by user ID
  async getProfileByUserId(userId: number) {
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
