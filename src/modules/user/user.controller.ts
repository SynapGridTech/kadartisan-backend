import { Controller, Get, UseGuards, Req, Param, ParseIntPipe } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { UsersService } from './providers/user.service';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';

@ApiTags('User')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard)
@Controller('user')
export class UserController {
  constructor(private readonly userService: UsersService) {}

  @Get('me')
  @ApiOperation({ summary: 'Get current authenticated user profile' })
  public async getProfile(@Req() req: any) {
    return this.userService.getProfileById(req.user.id);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get current user stats (requests & jobs breakdown by status)' })
  public async getStats(@Req() req: any) {
    return this.userService.getUserStats(req.user.id);
  }

  @Get('all')
  @ApiOperation({ summary: 'Get all registered users (customers & artisans)' })
  public async getAllUsers() {
    return this.userService.getAllUsers();
  }

  @Get('customers')
  @ApiOperation({ summary: 'Get all regular users (non-artisans)' })
  public async getRegularUsers() {
    return this.userService.getRegularUsers();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get full user details by ID (including bookings, jobs & profile)' })
  public async getUserById(@Param('id', ParseIntPipe) id: number) {
    return this.userService.getUserById(id);
  }
}
