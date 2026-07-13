import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class AdminUsersService {
  constructor(private prisma: PrismaService) {}

  private async findUserOrThrow(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { customerProfile: true, artisanProfile: true },
    });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  // ---------- 4.2 sub-tabs ----------
  public async getActivity(userId: string) {
    await this.findUserOrThrow(userId);
    return this.prisma.activityEvent.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getBookings(userId: string) {
    const user = await this.findUserOrThrow(userId);
    const customerId = user.customerProfile?.id;
    const artisanId = user.artisanProfile?.id;

    return this.prisma.serviceRequest.findMany({
      where: {
        OR: [
          customerId ? { customerId } : undefined,
          artisanId ? { acceptedArtisanId: artisanId } : undefined,
        ].filter(Boolean) as any,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getReviews(userId: string) {
    await this.findUserOrThrow(userId);
    return this.prisma.review.findMany({
      where: { OR: [{ authorId: userId }, { subjectId: userId }] },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getPosts(userId: string) {
    await this.findUserOrThrow(userId);
    return this.prisma.post.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getTransactions(userId: string) {
    await this.findUserOrThrow(userId);
    return this.prisma.transaction.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async getReports(userId: string) {
    await this.findUserOrThrow(userId);
    return this.prisma.complaint.findMany({
      where: { OR: [{ filedById: userId }, { againstId: userId }] },
      orderBy: { createdAt: 'desc' },
    });
  }

  // ---------- 4.2 notes ----------
  public async getNotes(userId: string) {
    await this.findUserOrThrow(userId);
    return this.prisma.adminNote.findMany({
      where: { subjectId: userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async addNote(userId: string, content: string, authorId?: string) {
    await this.findUserOrThrow(userId);
    return this.prisma.adminNote.create({
      data: { subjectId: userId, content, authorId: authorId ?? null },
    });
  }

  public async deleteNote(userId: string, noteId: string) {
    const note = await this.prisma.adminNote.findUnique({ where: { id: noteId } });
    if (!note || note.subjectId !== userId) {
      throw new NotFoundException('Note not found');
    }
    await this.prisma.adminNote.delete({ where: { id: noteId } });
    return { message: 'Note deleted successfully' };
  }

  // ---------- 4.3 actions ----------
  public async softDelete(userId: string, confirmName: string) {
    const user = await this.findUserOrThrow(userId);
    if (user.role === 'ADMIN') {
      throw new BadRequestException('Cannot delete an admin user');
    }
    if (user.fullName !== confirmName) {
      throw new BadRequestException('Confirmation name does not match user name');
    }
    await this.prisma.user.update({
      where: { id: userId },
      data: { deletedAt: new Date(), refreshToken: null },
    });
    return { message: 'User soft-deleted successfully' };
  }

  public async message(userId: string, content: string) {
    await this.findUserOrThrow(userId);
    // Recorded as an activity event; delivery handled by notification pipeline.
    const event = await this.prisma.activityEvent.create({
      data: { userId, type: 'admin_message', text: content },
    });
    return { message: 'Message sent', id: event.id };
  }

  public async setControls(userId: string, profileVisible: boolean) {
    await this.findUserOrThrow(userId);
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { profileVisible },
      select: { id: true, profileVisible: true },
    });
    return user;
  }

  public async flag(userId: string, flagged: boolean, reason?: string) {
    await this.findUserOrThrow(userId);
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { flagged, flagReason: flagged ? (reason ?? null) : null },
      select: { id: true, flagged: true, flagReason: true },
    });
    return user;
  }

  public async revokeVerification(userId: string, reason: string) {
    const user = await this.findUserOrThrow(userId);
    if (!user.artisanProfile) {
      throw new BadRequestException('User has no artisan verification to revoke');
    }
    await this.prisma.$transaction([
      this.prisma.user.update({ where: { id: userId }, data: { isVerified: false } }),
      this.prisma.artisanProfile.update({
        where: { userId },
        data: {
          artisanStatus: 'REJECTED',
          artisanRejectionReason: reason,
          artisanApprovedAt: null,
        },
      }),
    ]);
    return { message: 'Verification revoked successfully' };
  }
}
