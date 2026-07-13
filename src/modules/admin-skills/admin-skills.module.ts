import { Module } from '@nestjs/common';
import { AdminSkillsController } from './admin-skills.controller';
import { AdminSkillsService } from './providers/admin-skills.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AdminSkillsController],
  providers: [AdminSkillsService],
})
export class AdminSkillsModule {}
