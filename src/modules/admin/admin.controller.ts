import { Body, Controller, Get, Param, Patch, UseGuards } from '@nestjs/common';
import { Roles } from 'src/common/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { AdminService } from './admin.service';
import { Role } from '@prisma/client';

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Get('artisans/pending')
  getPendingArtisans() {
    return this.adminService.getPendingArtisans();
  }

  @Patch('artisans/:id/approve')
  approveArtisan(@Param('id') id: string) {
    return this.adminService.approveArtisan(Number(id));
  }

  @Patch('artisans/:id/reject')
  rejectArtisan(@Param('id') id: string, @Body('reason') reason?: string) {
    return this.adminService.rejectArtisan(Number(id), reason);
  }
}
