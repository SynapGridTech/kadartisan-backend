import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Post,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/database/prisma.service';

@Controller('bootstrap')
export class BootstrapController {
  constructor(private prisma: PrismaService) {}

  @Post('admin')
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

    const admin = await this.prisma.user.create({
      data: {
        email: body.email,
        password: hashedPassword,
        fullName: body.fullName,
        phoneNumber: body.phoneNumber,
        role: 'ADMIN',
      },
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
