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

  public async updateSkill(skillId: string, name?: string, category?: string) {
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

  public async deleteSkill(skillId: string) {
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

  // ========== USER MODERATION ==========

  private async findUserOrThrow(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        fullName: true,
        email: true,
        phoneNumber: true,
        role: true,
        suspendedUntil: true,
        suspensionReason: true,
        bannedAt: true,
        banReason: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.role === 'ADMIN') {
      throw new BadRequestException('Cannot moderate an admin user');
    }

    return user;
  }

  public async suspendUser(userId: string, days: number, reason: string) {
    const user = await this.findUserOrThrow(userId);

    if (user.bannedAt) {
      throw new BadRequestException('Cannot suspend a banned user. Unban first.');
    }

    const suspendedUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        suspendedUntil,
        suspensionReason: reason,
        refreshToken: null, // force logout
      },
    });

    return {
      message: `User suspended successfully`,
      user: {
        id: user.id,
        fullName: user.fullName,
        suspendedUntil,
        suspensionReason: reason,
      },
    };
  }

  public async unsuspendUser(userId: string) {
    const user = await this.findUserOrThrow(userId);

    if (!user.suspendedUntil) {
      throw new BadRequestException('User is not currently suspended');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        suspendedUntil: null,
        suspensionReason: null,
      },
    });

    return {
      message: 'User suspension lifted successfully',
      user: {
        id: user.id,
        fullName: user.fullName,
      },
    };
  }

  public async banUser(userId: string, reason: string) {
    const user = await this.findUserOrThrow(userId);

    if (user.bannedAt) {
      throw new BadRequestException('User is already banned');
    }

    const bannedAt = new Date();

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        bannedAt,
        banReason: reason,
        suspendedUntil: null,
        suspensionReason: null,
        refreshToken: null,
      },
    });

    return {
      message: 'User banned successfully',
      user: {
        id: user.id,
        fullName: user.fullName,
        bannedAt,
        banReason: reason,
      },
    };
  }

  public async unbanUser(userId: string) {
    const user = await this.findUserOrThrow(userId);

    if (!user.bannedAt) {
      throw new BadRequestException('User is not currently banned');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        bannedAt: null,
        banReason: null,
      },
    });

    return {
      message: 'User ban lifted successfully',
      user: {
        id: user.id,
        fullName: user.fullName,
      },
    };
  }

  // ========== MODERATION LISTS & APPEALS ==========

  public async getSuspendedUsers() {
    const users = await this.prisma.user.findMany({
      where: {
        suspendedUntil: { gt: new Date() },
      },
      select: {
        id: true,
        fullName: true,
        email: true,
        phoneNumber: true,
        role: true,
        suspendedUntil: true,
        suspensionReason: true,
        createdAt: true,
      },
      orderBy: { suspendedUntil: 'asc' },
    });

    return { users, count: users.length };
  }

  public async getBannedUsers() {
    const users = await this.prisma.user.findMany({
      where: {
        bannedAt: { not: null },
      },
      select: {
        id: true,
        fullName: true,
        email: true,
        phoneNumber: true,
        role: true,
        bannedAt: true,
        banReason: true,
        createdAt: true,
      },
      orderBy: { bannedAt: 'desc' },
    });

    return { users, count: users.length };
  }

  public async getAppeals() {
    const appeals = await this.prisma.appeal.findMany({
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            email: true,
            phoneNumber: true,
            role: true,
            suspendedUntil: true,
            suspensionReason: true,
            bannedAt: true,
            banReason: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return { appeals, count: appeals.length };
  }

  public async respondToAppeal(appealId: string, status: 'APPROVED' | 'REJECTED') {
    const appeal = await this.prisma.appeal.findUnique({
      where: { id: appealId },
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            suspendedUntil: true,
            bannedAt: true,
          },
        },
      },
    });

    if (!appeal) {
      throw new NotFoundException('Appeal not found');
    }

    if (appeal.status !== 'PENDING') {
      throw new BadRequestException(`Appeal has already been ${appeal.status.toLowerCase()}`);
    }

    await this.prisma.appeal.update({
      where: { id: appealId },
      data: { status },
    });

    if (status === 'APPROVED') {
      await this.prisma.user.update({
        where: { id: appeal.userId },
        data: {
          suspendedUntil: null,
          suspensionReason: null,
          bannedAt: null,
          banReason: null,
        },
      });
    }

    return {
      message: `Appeal ${status.toLowerCase()} successfully`,
      appeal: {
        id: appeal.id,
        userId: appeal.userId,
        userName: appeal.user.fullName,
        status,
      },
    };
  }
}
