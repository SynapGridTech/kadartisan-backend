import { Controller, Get, Injectable } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { HealthCheck, HealthCheckService, HealthIndicator, HealthCheckError } from '@nestjs/terminus';
import { PrismaService } from '../database/prisma.service';
import { EmailService } from '../modules/notification/providers/email.service';

@Injectable()
export class PrismaHealthIndicator extends HealthIndicator {
  constructor(private readonly prismaService: PrismaService) {
    super();
  }

  async isHealthy(key: string) {
    try {
      await this.prismaService.$queryRaw`SELECT 1`;
      return this.getStatus(key, true);
    } catch (error) {
      throw new HealthCheckError(
        'Prisma check failed',
        this.getStatus(key, false, { message: 'Database connection failed' })
      );
    }
  }
}

@Injectable()
export class EmailHealthIndicator extends HealthIndicator {
  constructor(private readonly emailService: EmailService) {
    super();
  }

  async isHealthy(key: string) {
    try {
      // Verify SMTP connection is working
      await this.emailService['transporter'].verify();
      return this.getStatus(key, true, { message: 'Email service is operational' });
    } catch (error) {
      throw new HealthCheckError(
        'Email check failed',
        this.getStatus(key, false, { message: 'Email SMTP connection failed', error: error.message })
      );
    }
  }
}

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private prismaHealth: PrismaHealthIndicator,
    private emailHealth: EmailHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({ summary: 'Health check - returns service readiness status' })
  readiness() {
    return this.health.check([
      async () => this.prismaHealth.isHealthy('database'),
      async () => this.emailHealth.isHealthy('mail'),
    ]);
  }
}