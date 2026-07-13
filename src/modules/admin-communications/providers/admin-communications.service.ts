import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { Prisma, TemplateType } from '@prisma/client';
import {
  BroadcastDto,
  CreateTemplateDto,
  MessageLogQueryDto,
  TemplatesQueryDto,
  UpdateTemplateDto,
} from '../dto/admin-communications.dto';

@Injectable()
export class AdminCommunicationsService {
  constructor(private prisma: PrismaService) {}

  // ---------- 10.1 broadcasts ----------
  private async audienceCount(audience?: string): Promise<number> {
    const where: Prisma.UserWhereInput = { deletedAt: null };
    if (audience === 'artisans') where.role = 'ARTISAN';
    else if (audience === 'customers') where.role = 'USER';
    return this.prisma.user.count({ where });
  }

  public async broadcast(dto: BroadcastDto) {
    const recipients = await this.audienceCount(dto.audience);

    const log = await this.prisma.messageLog.create({
      data: {
        channel: dto.channels.join(','),
        audience: dto.audience,
        subject: dto.subject,
        body: dto.body,
        recipients,
        status: 'SENT',
      },
    });

    return {
      broadcastId: log.id,
      recipients,
      channels: dto.channels,
      status: log.status,
    };
  }

  public async broadcastTest(dto: BroadcastDto) {
    await this.prisma.messageLog.create({
      data: {
        channel: dto.channels.join(','),
        audience: 'admin-test',
        subject: dto.subject,
        body: dto.body,
        recipients: 1,
        status: 'SENT',
        isTest: true,
      },
    });
    return { status: 'sent' };
  }

  public async estimate(channels?: string, audience?: string) {
    const recipients = await this.audienceCount(audience);
    const channelList = channels ? channels.split(',').filter(Boolean) : [];
    return {
      audience: audience ?? 'all',
      channels: channelList,
      estimatedRecipients: recipients,
    };
  }

  // ---------- 10.2 templates ----------
  public async listTemplates(query: TemplatesQueryDto) {
    const where: Prisma.MessageTemplateWhereInput = {};
    if (query.type) where.type = query.type.toUpperCase() as TemplateType;
    return this.prisma.messageTemplate.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getTemplate(id: string) {
    const template = await this.prisma.messageTemplate.findUnique({ where: { id } });
    if (!template) throw new NotFoundException('Template not found');
    return template;
  }

  public async createTemplate(dto: CreateTemplateDto) {
    return this.prisma.messageTemplate.create({
      data: {
        name: dto.name,
        subject: dto.subject,
        body: dto.body,
        channels: dto.channels,
        type: (dto.type ?? 'admin').toUpperCase() as TemplateType,
      },
    });
  }

  public async updateTemplate(id: string, dto: UpdateTemplateDto) {
    await this.getTemplate(id);
    return this.prisma.messageTemplate.update({
      where: { id },
      data: {
        ...(dto.name !== undefined && { name: dto.name }),
        ...(dto.subject !== undefined && { subject: dto.subject }),
        ...(dto.body !== undefined && { body: dto.body }),
        ...(dto.channels !== undefined && { channels: dto.channels }),
      },
    });
  }

  public async deleteTemplate(id: string) {
    await this.getTemplate(id);
    await this.prisma.messageTemplate.delete({ where: { id } });
    return { message: 'Template deleted successfully' };
  }

  // ---------- 10.3 message log ----------
  public async log(query: MessageLogQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const skip = (page - 1) * limit;

    const where: Prisma.MessageLogWhereInput = {};
    if (query.channel) where.channel = { contains: query.channel, mode: 'insensitive' };
    if (query.status) where.status = query.status as any;

    const [data, total] = await Promise.all([
      this.prisma.messageLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.messageLog.count({ where }),
    ]);
    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  public async getMessage(messageId: string) {
    const msg = await this.prisma.messageLog.findUnique({ where: { id: messageId } });
    if (!msg) throw new NotFoundException('Message not found');
    return msg;
  }

  public async summary() {
    const [total, sent, delivered, failed, bounced] = await Promise.all([
      this.prisma.messageLog.count(),
      this.prisma.messageLog.count({ where: { status: 'SENT' } }),
      this.prisma.messageLog.count({ where: { status: 'DELIVERED' } }),
      this.prisma.messageLog.count({ where: { status: 'FAILED' } }),
      this.prisma.messageLog.count({ where: { status: 'BOUNCED' } }),
    ]);
    const failureRatio = total > 0 ? Number((((failed + bounced) / total) * 100).toFixed(2)) : 0;
    return { total, sent, delivered, failed, bounced, failureRatio };
  }
}
