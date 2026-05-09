import { Module } from '@nestjs/common';
import { ArtisanController } from './artisan.controller';
import { ArtisanService } from './providers/artisan.service';
import { EmailService } from '../notification/providers/email.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [ArtisanController],
  providers: [ArtisanService, EmailService],
  exports: [ArtisanService],
})
export class ArtisanModule {}
