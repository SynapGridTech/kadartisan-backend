import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class AdminService {
  constructor(private prisma: PrismaService) {}

  // ========== SKILL MANAGEMENT ==========

  public async getAllSkills() {
    const skills = await this.prisma.skill.findMany({
      orderBy: { category: 'asc' },
    });

    const grouped = skills.reduce((acc, skill) => {
      const category = skill.category || 'Other';
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push({ id: skill.id, name: skill.name });
      return acc;
    }, {});

    return { skills: grouped };
  }

  public async createSkill(name: string, category?: string) {
    const existing = await this.prisma.skill.findUnique({
      where: { name },
    });

    if (existing) {
      throw new BadRequestException(`Skill '${name}' already exists`);
    }

    const skill = await this.prisma.skill.create({
      data: { name, category },
    });

    return {
      message: 'Skill created successfully',
      skill,
    };
  }

  public async updateSkill(skillId: number, name?: string, category?: string) {
    const skill = await this.prisma.skill.findUnique({
      where: { id: skillId },
    });

    if (!skill) {
      throw new NotFoundException('Skill not found');
    }

    if (name && name !== skill.name) {
      const existing = await this.prisma.skill.findUnique({
        where: { name },
      });
      if (existing) {
        throw new BadRequestException(`Skill '${name}' already exists`);
      }
    }

    const updated = await this.prisma.skill.update({
      where: { id: skillId },
      data: {
        ...(name && { name }),
        ...(category !== undefined && { category }),
      },
    });

    return {
      message: 'Skill updated successfully',
      skill: updated,
    };
  }

  public async deleteSkill(skillId: number) {
    const skill = await this.prisma.skill.findUnique({
      where: { id: skillId },
    });

    if (!skill) {
      throw new NotFoundException('Skill not found');
    }

    await this.prisma.skill.delete({
      where: { id: skillId },
    });

    return {
      message: 'Skill deleted successfully',
      skillId,
    };
  }
}
