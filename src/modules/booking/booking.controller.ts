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
  Query,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
} from '@nestjs/swagger';
import { BookingService } from './providers/booking.service';
import { CreateServiceRequestDto } from './dto/create-service-request.dto';
import { GetRequestsQueryDto } from './dto/get-requests-query.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@ApiTags('Booking')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('booking')
export class BookingController {
  constructor(private readonly bookingService: BookingService) {}

  //__________ CREATE NEW SERVICE REQUEST (client) ________________________
  @Post('request')
  @Roles(Role.USER, Role.ARTISAN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new service request' })
  public async createRequest(
    @Req() req: any,
    @Body() dto: CreateServiceRequestDto,
  ) {
    return this.bookingService.createRequest(req.user.id, dto);
  }

  //__________ GET CURRENT CLIENT'S REQUESTS ________________________
  @Get('requests')
  @Roles(Role.USER, Role.ARTISAN)
  @ApiOperation({ summary: "Get the current client's own service requests" })
  public async getRequests(
    @Req() req: any,
    @Query() query: GetRequestsQueryDto,
  ) {
    return this.bookingService.getMyRequests(req.user.id, query);
  }

  //__________ GET AVAILABLE SERVICE REQUESTS (artisans) ________________________
  @Get('requests/available')
  @Roles(Role.ARTISAN)
  @ApiOperation({ summary: 'Get available service requests matching the artisan skills or location' })
  public async getAvailableRequests(@Req() req: any) {
    return this.bookingService.getAvailableRequests(req.user.id);
  }

  //__________ ACCEPT A REQUEST (artisans) ________________________
  @Post('request/:id/accept')
  @Roles(Role.ARTISAN)
  @ApiOperation({ summary: 'Accept an available service request as an artisan' })
  public async acceptRequest(
    @Req() req: any,
    @Param('id', ParseUUIDPipe) requestId: string,
  ) {
    return this.bookingService.acceptRequest(req.user.id, requestId);
  }
}
