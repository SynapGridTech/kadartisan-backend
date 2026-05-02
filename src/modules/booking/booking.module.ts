import { Module } from '@nestjs/common';
import { BookingController } from './booking.controller';
import { BookingService } from './providers/booking.service';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [BookingController],
  providers: [BookingService],
  exports: [BookingService],
})
export class BookingModule {}