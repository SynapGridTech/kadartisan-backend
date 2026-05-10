import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { ApiOperation, ApiTags, ApiBody, ApiResponse } from '@nestjs/swagger';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/database/prisma.service';

@ApiTags('Bootstrap')
@Controller('bootstrap')
export class BootstrapController {
  constructor(private prisma: PrismaService) {}

  @Post('admin')
  @ApiOperation({ summary: 'Create the first admin user (one-time setup)' })
  @ApiBody({
    description: 'Admin registration details',
  })
 
  async createAdmin(
    @Body()
    body: {
      email: string;
      password: string;
      fullName: string;
      phoneNumber: string;
    },
  ) {
    const existingAdmin = await this.prisma.user.findFirst({
      where: { role: 'ADMIN' },
    });

    if (existingAdmin) {
      throw new HttpException('Admin already exists', HttpStatus.FORBIDDEN);
    }

    const hashedPassword = await bcrypt.hash(body.password, 10);

    const admin = await this.prisma.$transaction(async (tx) => {
      const createdAdmin = await tx.user.create({
        data: {
          email: body.email,
          password: hashedPassword,
          fullName: body.fullName,
          phoneNumber: body.phoneNumber,
          role: 'ADMIN',
          isVerified: true,
        },
      });

      await tx.adminProfile.create({
        data: { userId: createdAdmin.id },
      });

      return createdAdmin;
    });

    return {
      message: 'Admin created successfully',
      admin: {
        id: admin.id,
        email: admin.email,
        role: admin.role,
      },
    };
  }
}
