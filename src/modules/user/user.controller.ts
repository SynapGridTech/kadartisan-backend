import { Controller, Get, Patch, Body, UseGuards, Req, Param, ParseUUIDPipe } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { UsersService } from './providers/user.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@ApiTags('User')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('user')
export class UserController {
  constructor(private readonly userService: UsersService) {}

    //__________ROUTE TO GET CURRENT USER ________________________
  @Get('me')
  @ApiOperation({ summary: 'Get current authenticated user profile' })
  public async getProfile(@Req() req: any) {
    return this.userService.getProfileById(req.user.id);
  }

    //__________ROUTE TO UPDATE CURRENT USER PROFILE + ADDRESS ________________________
  @Patch('me')
  @ApiOperation({ summary: 'Update current user profile (name, avatar, contact) and customer location/address' })
  public async updateProfile(@Req() req: any, @Body() dto: UpdateUserDto) {
    return this.userService.updateProfile(req.user.id, dto);
  }

    //__________ROUTE TO GET USER STATS ________________________
  @Get('stats')
  @ApiOperation({ summary: 'Get current user stats (requests & jobs breakdown by status)' })
  public async getStats(@Req() req: any) {
    return this.userService.getUserStats(req.user.id);
  }

    //__________ROUTE TO GET ALL REGISTERED USERS (ADMIN only) ________________________
  @Get('all')
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Get all registered users (customers & artisans)' })
  public async getAllUsers() {
    return this.userService.getAllUsers();
  }

    //__________ROUTE TO GET ALL REGULAR USERS / CUSTOMERS (ADMIN only) ________________________
  @Get('customers')
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Get all regular users (non-artisans)' })
  public async getRegularUsers() {
    return this.userService.getRegularUsers();
  }

    //__________ROUTE TO GET FULL USERID ________________________
  @Get(':id')
  @ApiOperation({ summary: 'Get full user details by ID (including bookings, jobs & profile)' })
  public async getUserById(@Param('id', ParseUUIDPipe) id: string) {
    return this.userService.getUserById(id);
  }
}
