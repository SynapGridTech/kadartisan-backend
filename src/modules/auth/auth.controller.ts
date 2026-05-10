import {
  Controller,
  Post,
  Body,
  UnauthorizedException,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { RequestOtpDto } from './dto/request-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { CompleteRegistrationDto } from './dto/complete-registration.dto';
import { AuthService } from './providers/auth.service';
import { LoginDto } from '../user/dto/login.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { CreateAppealDto } from './dto/create-appeal.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  //__________ REQUEST OTP ________________________
  @Post('request-otp')
  @ApiOperation({ summary: 'Request OTP for registration or login' })
  @ApiResponse({ status: 200, description: 'OTP generated successfully' })
  public requestOtp(@Body() dto: RequestOtpDto) {
    return this.authService.requestOtp(dto.identifier, dto.channel, dto.role as any);
  }

    //__________ VERIFY OTP ________________________
  @Post('verify-otp')
  @ApiOperation({ summary: 'Verify OTP and receive temporary token' })
  public verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.authService.verifyOtp(dto.identifier, dto.otp, dto.channel, dto.role as any);
  }

    //__________ COMPLETE REGISTRATION  ________________________
  @Post('complete-registration')
  @ApiOperation({ summary: 'Complete user registration using temp token' })
  public complete(@Body() dto: CompleteRegistrationDto) {
    return this.authService.completeRegistration(dto);
  }

  
    //__________ 🔐 LOGIN ________________________
  @Post('login')
  @ApiOperation({ summary: 'Authenticate user and receive access & refresh tokens' })
  public async login(@Body() loginDto: LoginDto) {
    const { identifier, password, channel } = loginDto;
    return this.authService.login(identifier, password, channel);
  }

  
    //__________ 🔄 REFRESH TOKEN ________________________
  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  public async refresh(@Body() body: { refreshToken: string }) {
    if (!body.refreshToken) {
      throw new UnauthorizedException('Refresh token required');
    }
    const decoded = await this.authService.verifyRefreshToken(body.refreshToken);
    return this.authService.refresh(decoded.sub, body.refreshToken);
  }

  
    //__________ 🚪 LOGOUT (Protected) ________________________
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @ApiOperation({ summary: 'Logout user and invalidate refresh token' })
   logout(@Req() req) {
    return this.authService.logout(req.user.id);
  }

    //__________ FORGOT PASSWORD ________________________
  @Post('forgot-password')
  @ApiOperation({ summary: 'Request password reset OTP' })
  @ApiResponse({ status: 200, description: 'OTP sent if account exists' })
  requestReset(@Body() dto: RequestPasswordResetDto) {
    return this.authService.requestPasswordReset(dto.identifier, dto.channel);
  }

    //__________ VERIFY RESET OTP ________________________
  @Post('verify-reset-otp')
  @ApiOperation({ summary: 'Verify password reset OTP' })
   verifyResetOtp(@Body() dto: any) {
    return this.authService.verifyResetOtp(dto.identifier, dto.otp, dto.channel);
  }

    //__________ RESET PASSWORD  ________________________
  @Post('reset-password')
  @ApiOperation({ summary: 'Reset password using reset token' })
   resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }

    //__________ APPEAL SUBMISSION (Public) ________________________
  @Post('appeal')
  @ApiOperation({ summary: 'Submit an appeal for a suspended or banned account' })
  @ApiResponse({ status: 201, description: 'Appeal submitted successfully' })
  @ApiResponse({ status: 400, description: 'Account not found, not suspended, or appeal already pending' })
  submitAppeal(@Body() dto: CreateAppealDto) {
    return this.authService.submitAppeal(dto.identifier, dto.reason);
  }
}
