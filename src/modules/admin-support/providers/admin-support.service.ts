import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { Prisma, SupportTicketStatus } from '@prisma/client';
import {
  CreateArticleDto,
  CreateFaqDto,
  FaqSearchQueryDto,
  KnowledgeSearchQueryDto,
  ReplyTicketDto,
  TicketQueryDto,
  UpdateArticleDto,
} from '../dto/admin-support.dto';

@Injectable()
export class AdminSupportService {
  constructor(private prisma: PrismaService) {}

  private readonly statusToEnum: Record<string, SupportTicketStatus> = {
    Open: 'OPEN',
    'In Progress': 'IN_PROGRESS',
    Resolved: 'RESOLVED',
  };
  private readonly statusToLabel: Record<SupportTicketStatus, string> = {
    OPEN: 'Open',
    IN_PROGRESS: 'In Progress',
    RESOLVED: 'Resolved',
  };

  // ================= FAQs =================
  public async listFaqs(query: FaqSearchQueryDto) {
    const where: Prisma.FaqWhereInput = {};
    if (query.search) {
      where.OR = [
        { question: { contains: query.search, mode: 'insensitive' } },
        { answer: { contains: query.search, mode: 'insensitive' } },
      ];
    }
    return this.prisma.faq.findMany({ where, orderBy: { createdAt: 'desc' } });
  }

  public async createFaq(dto: CreateFaqDto) {
    const faq = await this.prisma.faq.create({ data: { ...dto } });
    return { faq };
  }

  public async updateFaq(id: string, dto: CreateFaqDto) {
    await this.findFaqOrThrow(id);
    const faq = await this.prisma.faq.update({ where: { id }, data: { ...dto } });
    return { faq };
  }

  public async deleteFaq(id: string) {
    await this.findFaqOrThrow(id);
    await this.prisma.faq.delete({ where: { id } });
    return { message: 'FAQ deleted' };
  }

  public async publishFaq(id: string, published: boolean) {
    await this.findFaqOrThrow(id);
    const faq = await this.prisma.faq.update({ where: { id }, data: { published } });
    return { faq };
  }

  public async faqStats() {
    const [totalFaqs, published, drafts, helpArticles] = await Promise.all([
      this.prisma.faq.count(),
      this.prisma.faq.count({ where: { published: true } }),
      this.prisma.faq.count({ where: { published: false } }),
      this.prisma.knowledgeArticle.count(),
    ]);
    return { totalFaqs, published, drafts, helpArticles };
  }

  private async findFaqOrThrow(id: string) {
    const faq = await this.prisma.faq.findUnique({ where: { id } });
    if (!faq) throw new NotFoundException('FAQ not found');
    return faq;
  }

  // ================= knowledge base =================
  public async listArticles(query: KnowledgeSearchQueryDto) {
    const where: Prisma.KnowledgeArticleWhereInput = {};
    if (query.category) where.category = query.category;
    if (query.search) {
      where.OR = [
        { title: { contains: query.search, mode: 'insensitive' } },
        { summary: { contains: query.search, mode: 'insensitive' } },
        { content: { contains: query.search, mode: 'insensitive' } },
      ];
    }
    return this.prisma.knowledgeArticle.findMany({ where, orderBy: { createdAt: 'desc' } });
  }

  public async createArticle(dto: CreateArticleDto) {
    const article = await this.prisma.knowledgeArticle.create({ data: { ...dto } });
    return { article };
  }

  public async updateArticle(id: string, dto: UpdateArticleDto) {
    const existing = await this.prisma.knowledgeArticle.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException('Article not found');
    const article = await this.prisma.knowledgeArticle.update({
      where: { id },
      data: {
        ...(dto.title !== undefined && { title: dto.title }),
        ...(dto.summary !== undefined && { summary: dto.summary }),
        ...(dto.content !== undefined && { content: dto.content }),
      },
    });
    return { article };
  }

  public async deleteArticle(id: string) {
    const existing = await this.prisma.knowledgeArticle.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException('Article not found');
    await this.prisma.knowledgeArticle.delete({ where: { id } });
    return { message: 'Article deleted' };
  }

  // ================= support tickets =================
  private serializeTicket(ticket: any) {
    return { ...ticket, status: this.statusToLabel[ticket.status as SupportTicketStatus] };
  }

  public async listTickets(query: TicketQueryDto) {
    const page = query.page ?? 1;
    const limit = 20;
    const skip = (page - 1) * limit;

    const where: Prisma.SupportTicketWhereInput = {};
    if (query.status) where.status = this.statusToEnum[query.status];
    if (query.priority) where.priority = query.priority;

    const [rows, total] = await Promise.all([
      this.prisma.supportTicket.findMany({
        where,
        include: { user: { select: { id: true, fullName: true, email: true } } },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.supportTicket.count({ where }),
    ]);
    return { data: rows.map((t) => this.serializeTicket(t)), total };
  }

  public async getTicket(id: string) {
    const ticket = await this.prisma.supportTicket.findUnique({
      where: { id },
      include: {
        user: { select: { id: true, fullName: true, email: true } },
        messages: { orderBy: { createdAt: 'asc' } },
      },
    });
    if (!ticket) throw new NotFoundException('Ticket not found');
    return this.serializeTicket(ticket);
  }

  public async updateStatus(id: string, status: 'Open' | 'In Progress' | 'Resolved') {
    const existing = await this.prisma.supportTicket.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException('Ticket not found');
    const ticket = await this.prisma.supportTicket.update({
      where: { id },
      data: { status: this.statusToEnum[status] },
    });
    return { ticket: this.serializeTicket(ticket) };
  }

  public async reply(id: string, message: string) {
    const existing = await this.prisma.supportTicket.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException('Ticket not found');
    const reply = await this.prisma.supportMessage.create({
      data: { ticketId: id, sender: 'admin', message },
    });
    // Replying moves an Open ticket into progress.
    if (existing.status === 'OPEN') {
      await this.prisma.supportTicket.update({
        where: { id },
        data: { status: 'IN_PROGRESS' },
      });
    }
    return { reply };
  }
}
