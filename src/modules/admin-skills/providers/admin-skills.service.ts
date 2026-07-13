import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { Prisma } from '@prisma/client';
import {
  CreateSkillCategoryDto,
  ListSkillsQueryDto,
  SkillFormDto,
  UpdateSkillFormDto,
} from '../dto/admin-skills.dto';

@Injectable()
export class AdminSkillsService {
  constructor(private prisma: PrismaService) {}

  // ---------- skills ----------
  public async list(query: ListSkillsQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const skip = (page - 1) * limit;

    const where: Prisma.SkillWhereInput = {};
    if (query.status) where.status = query.status === 'active' ? 'ACTIVE' : 'INACTIVE';
    if (query.category) {
      where.OR = [{ category: query.category }, { categoryRefId: query.category }];
    }
    if (query.search) {
      where.name = { contains: query.search, mode: 'insensitive' };
    }

    const [items, total] = await Promise.all([
      this.prisma.skill.findMany({
        where,
        include: { categoryRef: true, _count: { select: { artisans: true } } },
        orderBy: { name: 'asc' },
        skip,
        take: limit,
      }),
      this.prisma.skill.count({ where }),
    ]);

    return { items, total };
  }

  public async metrics() {
    const [totalSkills, activeSkills, inactiveSkills, categories, assignments] =
      await Promise.all([
        this.prisma.skill.count(),
        this.prisma.skill.count({ where: { status: 'ACTIVE' } }),
        this.prisma.skill.count({ where: { status: 'INACTIVE' } }),
        this.prisma.skillCategory.count(),
        this.prisma.artisanSkill.count(),
      ]);
    return { totalSkills, activeSkills, inactiveSkills, categories, assignments };
  }

  private async resolveCategoryId(categoryId?: string, category?: string) {
    if (categoryId) return categoryId;
    if (category) {
      const existing = await this.prisma.skillCategory.findUnique({
        where: { name: category },
      });
      if (existing) return existing.id;
      const created = await this.prisma.skillCategory.create({ data: { name: category } });
      return created.id;
    }
    return undefined;
  }

  public async create(dto: SkillFormDto) {
    const existing = await this.prisma.skill.findUnique({ where: { name: dto.name } });
    if (existing) throw new BadRequestException(`Skill '${dto.name}' already exists`);

    const categoryRefId = await this.resolveCategoryId(dto.categoryId, dto.category);

    return this.prisma.skill.create({
      data: {
        name: dto.name,
        description: dto.description,
        icon: dto.icon,
        category: dto.category,
        categoryRefId,
      },
      include: { categoryRef: true },
    });
  }

  public async update(id: string, dto: UpdateSkillFormDto) {
    const skill = await this.prisma.skill.findUnique({ where: { id } });
    if (!skill) throw new NotFoundException('Skill not found');

    if (dto.name && dto.name !== skill.name) {
      const clash = await this.prisma.skill.findUnique({ where: { name: dto.name } });
      if (clash) throw new BadRequestException(`Skill '${dto.name}' already exists`);
    }

    const categoryRefId =
      dto.categoryId || dto.category
        ? await this.resolveCategoryId(dto.categoryId, dto.category)
        : undefined;

    return this.prisma.skill.update({
      where: { id },
      data: {
        ...(dto.name !== undefined && { name: dto.name }),
        ...(dto.description !== undefined && { description: dto.description }),
        ...(dto.icon !== undefined && { icon: dto.icon }),
        ...(dto.category !== undefined && { category: dto.category }),
        ...(categoryRefId !== undefined && { categoryRefId }),
      },
      include: { categoryRef: true },
    });
  }

  public async remove(id: string) {
    const skill = await this.prisma.skill.findUnique({
      where: { id },
      include: { _count: { select: { artisans: true } } },
    });
    if (!skill) throw new NotFoundException('Skill not found');
    if (skill._count.artisans > 0) {
      throw new BadRequestException('Cannot delete a skill assigned to artisans');
    }
    await this.prisma.skill.delete({ where: { id } });
    return { message: 'Skill deleted successfully' };
  }

  public async setStatus(id: string, status: 'active' | 'inactive') {
    const skill = await this.prisma.skill.findUnique({ where: { id } });
    if (!skill) throw new NotFoundException('Skill not found');
    return this.prisma.skill.update({
      where: { id },
      data: { status: status === 'active' ? 'ACTIVE' : 'INACTIVE' },
    });
  }

  // ---------- categories ----------
  public async listCategories() {
    return this.prisma.skillCategory.findMany({
      include: { _count: { select: { skills: true } } },
      orderBy: { name: 'asc' },
    });
  }

  public async createCategory(dto: CreateSkillCategoryDto) {
    const existing = await this.prisma.skillCategory.findUnique({
      where: { name: dto.name },
    });
    if (existing) throw new BadRequestException('Category already exists');
    return this.prisma.skillCategory.create({ data: { name: dto.name } });
  }
}
