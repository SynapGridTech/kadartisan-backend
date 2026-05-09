import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { AdminService } from './providers/admin.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AdminController],
  providers: [AdminService]
})
export class AdminModule {}
