import { Module } from '@nestjs/common';
import { BootstrapController } from './bootstrap.controller';
import { PrismaService } from 'src/database/prisma.service';

@Module({
  controllers: [BootstrapController],
  providers: [PrismaService],
})
export class BootstrapModule {}
