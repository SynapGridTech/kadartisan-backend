import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam, ApiHeader } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminTransactionsService } from './providers/admin-transactions.service';
import { InitiateRefundDto, ListTransactionsQueryDto } from './dto/admin-transactions.dto';

// ---------- 6.1 Transaction monitoring (GET /api/admin/transactions) ----------
@ApiTags('Admin Transactions')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/transactions')
export class AdminTransactionsController {
  constructor(private readonly service: AdminTransactionsService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated transaction list' })
  list(@Query() query: ListTransactionsQueryDto) {
    return this.service.list(query);
  }
}

// ---------- 6.2 Administrative refunds (/admin/transactions/*) ----------
@ApiTags('Admin Transactions')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin/transactions')
export class AdminRefundsController {
  constructor(private readonly service: AdminTransactionsService) {}

  @Post(':transactionId/refund')
  @ApiOperation({ summary: 'Refund customer payment (idempotent)' })
  @ApiParam({ name: 'transactionId', type: 'string' })
  @ApiHeader({ name: 'X-Idempotency-Key', required: true })
  refund(
    @Param('transactionId', ParseUUIDPipe) transactionId: string,
    @Headers('x-idempotency-key') idempotencyKey: string,
    @Body() dto: InitiateRefundDto,
  ) {
    return this.service.initiateRefund(transactionId, idempotencyKey, dto);
  }

  @Get('refunds/:refundId/status')
  @ApiOperation({ summary: 'Query status of a gateway refund' })
  @ApiParam({ name: 'refundId', type: 'string' })
  refundStatus(@Param('refundId', ParseUUIDPipe) refundId: string) {
    return this.service.getRefundStatus(refundId);
  }

  @Get(':transactionId')
  @ApiOperation({ summary: 'Fetch refund metadata for a transaction' })
  @ApiParam({ name: 'transactionId', type: 'string' })
  metadata(@Param('transactionId', ParseUUIDPipe) transactionId: string) {
    return this.service.getRefundMetadata(transactionId);
  }
}

// ---------- 6.2 Refund policy (/admin/settings/payment/refund-policy) ----------
@ApiTags('Admin Transactions')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin/settings/payment')
export class AdminRefundPolicyController {
  constructor(private readonly service: AdminTransactionsService) {}

  @Get('refund-policy')
  @ApiOperation({ summary: 'Fetch active commission & refund guidelines' })
  refundPolicy() {
    return this.service.getRefundPolicy();
  }
}
