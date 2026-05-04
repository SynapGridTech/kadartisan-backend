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
  ParseIntPipe,
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
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('booking')
export class BookingController {
  constructor(private readonly bookingService: BookingService) {}

  @Post('request')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new service request' })
  @ApiResponse({ status: 201, description: 'Service request created successfully' })
  @ApiResponse({ status: 400, description: 'Bad request - invalid input or user not found' })
  async createRequest(
    @Req() req: any,
    @Body() dto: CreateServiceRequestDto,
  ) {
    return this.bookingService.createRequest(req.user.id, dto);
  }

  @Get('requests')
  @ApiOperation({ summary: 'Get all service requests with optional filters' })
  @ApiResponse({ status: 200, description: 'List of service requests returned' })
  @ApiBody({
    description: 'Optional filters for service requests',
    required: false,
    schema: {
      type: 'object',
      properties: {
        state: { type: 'string', example: 'Kaduna' },
        skillRequired: { type: 'string', example: 'Electrician' },
        status: { type: 'string', example: 'PENDING', enum: ['PENDING', 'MATCHED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'] },
      },
    },
  })
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
  @ApiOperation({ summary: 'Search approved artisans by skill and location' })
  @ApiResponse({ status: 200, description: 'List of matching artisans returned' })
  @ApiBody({
    description: 'Filters for artisan search',
    required: false,
    schema: {
      type: 'object',
      properties: {
        skill: { type: 'string', example: 'Electrician' },
        serviceLocation: { type: 'string', example: 'Kaduna North' },
      },
    },
  })
  async searchArtisans(
    @Req() req: any,
    @Body() filters: {
      skill?: string;
      serviceLocation?: string;
    },
  ) {
    return this.bookingService.searchArtisans(filters);
  }

  @Get('requests/available')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ARTISAN)
  @ApiOperation({ summary: 'Get available service requests for artisans (matching skills or state)' })
  @ApiResponse({ status: 200, description: 'List of available PENDING requests returned' })
  @ApiResponse({ status: 403, description: 'Forbidden - user is not an approved artisan' })
  async getAvailableRequests(@Req() req: any) {
    return this.bookingService.getAvailableRequests(req.user.id);
  }

  @Post('request/:id/accept')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ARTISAN)
  @ApiOperation({ summary: 'Accept a service request as an artisan' })
  @ApiParam({ name: 'id', description: 'Service request ID', type: 'number', example: 1 })
  @ApiResponse({ status: 200, description: 'Request accepted successfully - status changed to MATCHED' })
  @ApiResponse({ status: 400, description: 'Bad request - request not found or already processed' })
  @ApiResponse({ status: 403, description: 'Forbidden - user is not an approved artisan' })
  async acceptRequest(
    @Req() req: any,
    @Param('id', ParseIntPipe) requestId: number,
  ) {
    return this.bookingService.acceptRequest(req.user.id, requestId);
  }
}
