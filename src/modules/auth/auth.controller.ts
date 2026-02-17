import {
  Controller,
  Post,
  Body,
  UnauthorizedException,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { RequestOtpDto } from './dto/request-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { CompleteRegistrationDto } from './dto/complete-registration.dto';
import { AuthService } from './providers/auth.service';
import { LoginDto } from '../user/dto/login.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('request-otp')
  public requestOtp(@Body() dto: RequestOtpDto) {
    return this.authService.requestOtp(dto.identifier, dto.channel);
  }

  @Post('verify-otp')
  public verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.authService.verifyOtp(dto.identifier, dto.otp, dto.channel);
  }

  @Post('complete-registration')
  public complete(@Body() dto: CompleteRegistrationDto) {
    return this.authService.completeRegistration(dto);
  }

  // 🔐 LOGIN
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const { identifier, password, channel } = loginDto;

    return this.authService.login(identifier, password, channel);
  }

  // 🔄 REFRESH TOKEN
  @Post('refresh')
  async refresh(@Body() body: { refreshToken: string }) {
    if (!body.refreshToken) {
      throw new UnauthorizedException('Refresh token required');
    }

    const decoded = await this.authService.verifyRefreshToken(
      body.refreshToken,
    );

    return this.authService.refresh(decoded.sub, body.refreshToken);
  }

  // 🚪 LOGOUT (Protected)
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req) {
    return this.authService.logout(req.user.id);
  }

  @Post('forgot-password')
  requestReset(@Body() dto: RequestPasswordResetDto) {
    return this.authService.requestPasswordReset(dto.identifier, dto.channel);
  }

  @Post('verify-reset-otp')
  verifyResetOtp(@Body() dto: any) {
    return this.authService.verifyResetOtp(
      dto.identifier,
      dto.otp,
      dto.channel,
    );
  }

  @Post('reset-password')
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }
}
