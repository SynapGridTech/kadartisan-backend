import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiBody,
} from '@nestjs/swagger';
import { BookingService } from './providers/booking.service';
import { CreateServiceRequestDto } from './dto/create-service-request.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@ApiTags('Booking')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard)
@Controller('booking')
export class BookingController {
  constructor(private readonly bookingService: BookingService) {}

  //__________ CREATE NEW SERVICE REQUEST (customer) ________________________
  @Post('request')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new service request' })
   public async createRequest(
    @Req() req: any,
    @Body() dto: CreateServiceRequestDto,
  ) {
    return this.bookingService.createRequest(req.user.id, dto);
  }


  //__________ GET ALL REQUESTS  ________________________
  @Get('requests')
  @ApiOperation({ summary: 'Get all service requests with optional filters' })
  public async getRequests(
    @Req() req: any,
    @Body() filters?: {
      state?: string;
      skillRequired?: string;
      status?: string;
    },
  ) {
    return this.bookingService.getRequests(filters);
  }

  //__________ GET AVAILABLE SERVICES REQUEST (pendings)________________________
  @Get('requests/available')
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(Role.ARTISAN)
  @ApiOperation({ summary: 'Get available service requests for artisans (matching skills or state)' })
  public async getAvailableRequests(@Req() req: any) {
    return this.bookingService.getAvailableRequests(req.user.id);
  }

  //__________ACCEPT A REQUEST ________________________
  @Post('request/:id/accept')
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(Role.ARTISAN)
  @ApiOperation({ summary: 'Accept a service request as an artisan' })
   public async acceptRequest(
    @Req() req: any,
    @Param('id', ParseUUIDPipe) requestId: string,
  ) {
    return this.bookingService.acceptRequest(req.user.id, requestId);
  }
}
