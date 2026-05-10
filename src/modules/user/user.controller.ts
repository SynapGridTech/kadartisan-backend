import { Controller, Get, UseGuards, Req, Param, ParseUUIDPipe } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { UsersService } from './providers/user.service';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';

@ApiTags('User')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard)
@Controller('user')
export class UserController {
  constructor(private readonly userService: UsersService) {}

    //__________ROUTE TO GET CURRENT USER ________________________
  @Get('me')
  @ApiOperation({ summary: 'Get current authenticated user profile' })
  public async getProfile(@Req() req: any) {
    return this.userService.getProfileById(req.user.id);
  }

    //__________ROUTE TO GET USER STATS ________________________
  @Get('stats')
  @ApiOperation({ summary: 'Get current user stats (requests & jobs breakdown by status)' })
  public async getStats(@Req() req: any) {
    return this.userService.getUserStats(req.user.id);
  }

    //__________ROUTE TO GET ALL REGISTERED USERS ________________________
  @Get('all')
  @ApiOperation({ summary: 'Get all registered users (customers & artisans)' })
  public async getAllUsers() {
    return this.userService.getAllUsers();
  }

    //__________ROUTE TO GET ALL REGULAR USERS (non-artisans) ________________________
  @Get('customers')
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
