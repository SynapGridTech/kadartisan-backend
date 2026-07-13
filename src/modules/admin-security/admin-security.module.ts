import { Module } from '@nestjs/common';
import { AdminSecurityController } from './admin-security.controller';
import { AdminSecurityService } from './providers/admin-security.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AdminSecurityController],
  providers: [AdminSecurityService],
})
export class AdminSecurityModule {}
