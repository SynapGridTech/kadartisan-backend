import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { CreateConversationDto } from '../dto/create-conversation.dto';
import { SendMessageDto } from '../dto/send-message.dto';

@Injectable()
export class ConversationService {
  constructor(private prisma: PrismaService) {}

  //________________ Shape a participant User record for API responses
  private shapeParticipant(user: any) {
    if (!user) return null;
    return {
      id: user.id,
      fullName: user.fullName,
      profilePicture: user.profilePicture,
      role: user.role,
    };
  }

  //________________ Shape a conversation for API responses, from the caller's perspective
  private shapeConversation(convo: any, currentUserId: string) {
    const isCustomer = convo.customerUserId === currentUserId;
    const other = isCustomer ? convo.artisanUser : convo.customerUser;
    const lastMessage = convo.messages?.[0] ?? null;

    return {
      id: convo.id,
      requestId: convo.requestId ?? null,
      participant: this.shapeParticipant(other),
      lastMessage: lastMessage
        ? {
            id: lastMessage.id,
            body: lastMessage.body,
            senderUserId: lastMessage.senderUserId,
            createdAt: lastMessage.createdAt.toISOString(),
          }
        : null,
      unreadCount: convo._count?.messages ?? 0,
      lastMessageAt: convo.lastMessageAt.toISOString(),
      createdAt: convo.createdAt.toISOString(),
    };
  }

  //________________ Resolve which side of a conversation the two users sit on.
  // A conversation always has one customer-side user and one artisan-side user.
  // We derive the pairing from the caller's role so either party can open a thread.
  private async resolvePairing(callerUserId: string, recipientUserId: string) {
    if (callerUserId === recipientUserId) {
      throw new BadRequestException(
        'Cannot start a conversation with yourself',
      );
    }

    const [caller, recipient] = await Promise.all([
      this.prisma.user.findUnique({ where: { id: callerUserId } }),
      this.prisma.user.findUnique({ where: { id: recipientUserId } }),
    ]);

    if (!caller) throw new NotFoundException('Caller account not found');
    if (!recipient) throw new NotFoundException('Recipient account not found');

    // Determine the customer/artisan split. The artisan side is whichever
    // participant has the ARTISAN role; the other is treated as the customer.
    let customerUserId: string;
    let artisanUserId: string;

    if (caller.role === 'ARTISAN' && recipient.role !== 'ARTISAN') {
      artisanUserId = caller.id;
      customerUserId = recipient.id;
    } else if (recipient.role === 'ARTISAN' && caller.role !== 'ARTISAN') {
      artisanUserId = recipient.id;
      customerUserId = caller.id;
    } else if (caller.role === 'ARTISAN' && recipient.role === 'ARTISAN') {
      // Two artisans: keep a stable ordering so the same pair always maps to one thread.
      [customerUserId, artisanUserId] = [caller.id, recipient.id].sort();
    } else {
      // Two customers.
      [customerUserId, artisanUserId] = [caller.id, recipient.id].sort();
    }

    return { customerUserId, artisanUserId };
  }

  //________________ LOGIC to find-or-create a conversation between two users
  public async createOrGetConversation(
    userId: string,
    dto: CreateConversationDto,
  ) {
    const { customerUserId, artisanUserId } = await this.resolvePairing(
      userId,
      dto.recipientUserId,
    );

    // Validate the optional request link exists.
    if (dto.requestId) {
      const request = await this.prisma.serviceRequest.findUnique({
        where: { id: dto.requestId },
      });
      if (!request) throw new NotFoundException('Service request not found');
    }

    // Find-or-create. We do this explicitly rather than via upsert because
    // Postgres treats NULL as distinct in a unique index, so a composite unique
    // on a nullable requestId cannot reliably dedupe request-less threads.
    let convo = await this.prisma.conversation.findFirst({
      where: {
        customerUserId,
        artisanUserId,
        requestId: dto.requestId ?? null,
      },
    });

    if (!convo) {
      convo = await this.prisma.conversation.create({
        data: {
          customerUserId,
          artisanUserId,
          requestId: dto.requestId ?? null,
        },
      });
    }

    // Optionally send a first message.
    if (dto.message && dto.message.trim().length > 0) {
      await this.sendMessage(userId, convo.id, { body: dto.message });
    }

    return this.getConversationById(userId, convo.id);
  }

  //________________ Guard: load a conversation and ensure the caller participates
  private async requireParticipant(userId: string, conversationId: string) {
    const convo = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
    });

    if (!convo) throw new NotFoundException('Conversation not found');

    if (convo.customerUserId !== userId && convo.artisanUserId !== userId) {
      throw new ForbiddenException('You are not part of this conversation');
    }

    return convo;
  }

  //________________ LOGIC to list the caller's conversations, newest activity first
  public async getConversations(userId: string, query?: { page?: number }) {
    const page = query?.page && query.page > 0 ? query.page : 1;
    const pageSize = 20;
    const skip = (page - 1) * pageSize;

    const where = {
      OR: [{ customerUserId: userId }, { artisanUserId: userId }],
    };

    const [total, conversations] = await this.prisma.$transaction([
      this.prisma.conversation.count({ where }),
      this.prisma.conversation.findMany({
        where,
        include: {
          customerUser: {
            select: {
              id: true,
              fullName: true,
              profilePicture: true,
              role: true,
            },
          },
          artisanUser: {
            select: {
              id: true,
              fullName: true,
              profilePicture: true,
              role: true,
            },
          },
          messages: {
            orderBy: { createdAt: 'desc' },
            take: 1,
          },
          // Unread = messages the caller did not send and has not read.
          _count: {
            select: {
              messages: {
                where: {
                  readAt: null,
                  NOT: { senderUserId: userId },
                },
              },
            },
          },
        } as any,
        orderBy: { lastMessageAt: 'desc' },
        skip,
        take: pageSize,
      }),
    ]);

    return {
      count: total,
      page,
      pageSize,
      conversations: conversations.map((c) =>
        this.shapeConversation(c, userId),
      ),
    };
  }

  //________________ LOGIC to fetch a single conversation (caller must participate)
  public async getConversationById(userId: string, conversationId: string) {
    await this.requireParticipant(userId, conversationId);

    const convo = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
      include: {
        customerUser: {
          select: {
            id: true,
            fullName: true,
            profilePicture: true,
            role: true,
          },
        },
        artisanUser: {
          select: {
            id: true,
            fullName: true,
            profilePicture: true,
            role: true,
          },
        },
        messages: {
          orderBy: { createdAt: 'desc' },
          take: 1,
        },
        _count: {
          select: {
            messages: {
              where: { readAt: null, NOT: { senderUserId: userId } },
            },
          },
        },
      } as any,
    });

    return this.shapeConversation(convo, userId);
  }

  //________________ LOGIC to list messages in a conversation, marking them read
  public async getMessages(
    userId: string,
    conversationId: string,
    query?: { page?: number },
  ) {
    await this.requireParticipant(userId, conversationId);

    const page = query?.page && query.page > 0 ? query.page : 1;
    const pageSize = 30;
    const skip = (page - 1) * pageSize;

    const [total, messages] = await this.prisma.$transaction([
      this.prisma.message.count({ where: { conversationId } }),
      this.prisma.message.findMany({
        where: { conversationId },
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
      }),
    ]);

    // Mark the caller's inbound messages as read.
    await this.prisma.message.updateMany({
      where: {
        conversationId,
        readAt: null,
        NOT: { senderUserId: userId },
      },
      data: { readAt: new Date() },
    });

    return {
      count: total,
      page,
      pageSize,
      // Return oldest-first within the page for natural chat rendering.
      messages: messages.reverse().map((m) => ({
        id: m.id,
        conversationId: m.conversationId,
        senderUserId: m.senderUserId,
        body: m.body,
        readAt: m.readAt ? m.readAt.toISOString() : null,
        createdAt: m.createdAt.toISOString(),
        mine: m.senderUserId === userId,
      })),
    };
  }

  //________________ LOGIC to send a message into a conversation
  public async sendMessage(
    userId: string,
    conversationId: string,
    dto: SendMessageDto,
  ) {
    await this.requireParticipant(userId, conversationId);

    const [message] = await this.prisma.$transaction([
      this.prisma.message.create({
        data: {
          conversationId,
          senderUserId: userId,
          body: dto.body,
        },
      }),
      this.prisma.conversation.update({
        where: { id: conversationId },
        data: { lastMessageAt: new Date() },
      }),
    ]);

    return {
      id: message.id,
      conversationId: message.conversationId,
      senderUserId: message.senderUserId,
      body: message.body,
      readAt: null,
      createdAt: message.createdAt.toISOString(),
      mine: true,
    };
  }
}
