import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { BookingService } from './providers/booking.service';
import { CreateServiceRequestDto } from './dto/create-service-request.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';

@ApiTags('Booking')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('booking')
export class BookingController {
  constructor(private readonly bookingService: BookingService) {}

  @Post('request')
  @HttpCode(HttpStatus.CREATED)
  async createRequest(
    @Req() req: any,
    @Body() dto: CreateServiceRequestDto,
  ) {
    return this.bookingService.createRequest(req.user.id, dto);
  }

  @Get('requests')
  async getRequests(
    @Req() req: any,
    @Body() filters?: {
      state?: string;
      skillRequired?: string;
      status?: string;
    },
  ) {
    return this.bookingService.getRequests(filters);
  }

  @Get('artisans')
  async searchArtisans(
    @Req() req: any,
    @Body() filters: {
      skill?: string;
      state?: string;
      lga?: string;
    },
  ) {
    return this.bookingService.searchArtisans(filters);
  }
}
