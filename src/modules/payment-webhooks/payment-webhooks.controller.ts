import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { PaymentWebhooksService } from './providers/payment-webhooks.service';

// Inbound gateway callbacks — intentionally public (no admin JWT), per spec section 17.
@ApiTags('Payment Webhooks')
@Controller('webhooks')
export class PaymentWebhooksController {
  constructor(private readonly service: PaymentWebhooksService) {}

  @Post('payment/success')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Gateway callback: customer deposit succeeded' })
  paymentSuccess(@Body() payload: any) {
    return this.service.handlePaymentSuccess(payload);
  }

  @Post('payment/failed')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Gateway callback: customer deposit failed' })
  paymentFailed(@Body() payload: any) {
    return this.service.handlePaymentFailed(payload);
  }

  @Post('payout/completed')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Gateway callback: artisan payout completed' })
  payoutCompleted(@Body() payload: any) {
    return this.service.handlePayoutCompleted(payload);
  }
}
