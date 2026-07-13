import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam, ApiConsumes } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminSettingsService } from './providers/admin-settings.service';
import {
  BusinessSettingsDto,
  CurrencySettingsDto,
  DataSettingsDto,
  FeeStructureDto,
  LocalizationDto,
  NotificationsConfigDto,
  PayoutSettingsDto,
  PlatformSettingsDto,
  TestWebhookDto,
  ToggleGatewayDto,
  UpdateGatewayDto,
  WebhookSettingsDto,
} from './dto/admin-settings.dto';

@ApiTags('Admin Settings')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('settings')
export class AdminSettingsController {
  constructor(private readonly service: AdminSettingsService) {}

  // ================= 13 payment =================
  @Get('payment/gateways')
  @ApiOperation({ summary: 'List payment gateways configuration' })
  listGateways() {
    return this.service.listGateways();
  }

  @Put('payment/gateways/:id')
  @ApiOperation({ summary: 'Update gateway API keys & emails' })
  @ApiParam({ name: 'id', type: 'string' })
  updateGateway(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateGatewayDto) {
    return this.service.updateGateway(id, dto);
  }

  @Put('payment/gateways/:id/toggle')
  @ApiOperation({ summary: 'Enable / disable gateway status' })
  @ApiParam({ name: 'id', type: 'string' })
  toggleGateway(@Param('id', ParseUUIDPipe) id: string, @Body() dto: ToggleGatewayDto) {
    return this.service.toggleGateway(id, dto.active);
  }

  @Get('payment/fee-structure')
  @ApiOperation({ summary: 'Fetch current platform commission rates' })
  getFeeStructure() {
    return this.service.getFeeStructure();
  }

  @Put('payment/fee-structure')
  @ApiOperation({ summary: 'Update platform commission rules' })
  updateFeeStructure(@Body() dto: FeeStructureDto) {
    return this.service.updateFeeStructure(dto);
  }

  @Get('payment/payout')
  @ApiOperation({ summary: 'Fetch automatic payout threshold configuration' })
  getPayout() {
    return this.service.getPayout();
  }

  @Put('payment/payout')
  @ApiOperation({ summary: 'Update automatic payout triggers' })
  updatePayout(@Body() dto: PayoutSettingsDto) {
    return this.service.updatePayout(dto);
  }

  @Get('payment/currency')
  @ApiOperation({ summary: 'Fetch supported currencies & txn limits' })
  getCurrency() {
    return this.service.getCurrency();
  }

  @Put('payment/currency')
  @ApiOperation({ summary: 'Update currencies & limit criteria' })
  updateCurrency(@Body() dto: CurrencySettingsDto) {
    return this.service.updateCurrency(dto);
  }

  @Get('payment/webhooks')
  @ApiOperation({ summary: 'Fetch URLs registered at the gateway' })
  getWebhooks() {
    return this.service.getWebhooks();
  }

  @Put('payment/webhooks')
  @ApiOperation({ summary: 'Update webhook callback endpoints' })
  updateWebhooks(@Body() dto: WebhookSettingsDto) {
    return this.service.updateWebhooks(dto);
  }

  @Post('payment/webhooks/test')
  @ApiOperation({ summary: 'Trigger sandbox webhook event' })
  testWebhook(@Body() dto: TestWebhookDto) {
    return this.service.testWebhook(dto.event);
  }

  // ================= 14 general =================
  @Get('platform')
  @ApiOperation({ summary: 'Fetch registrations, verification & maintenance statuses' })
  getPlatform() {
    return this.service.getPlatform();
  }

  @Put('platform')
  @ApiOperation({ summary: 'Update main platform switches' })
  updatePlatform(@Body() dto: PlatformSettingsDto) {
    return this.service.updatePlatform(dto);
  }

  @Get('business')
  @ApiOperation({ summary: 'Get business address and phone info' })
  getBusiness() {
    return this.service.getBusiness();
  }

  @Put('business')
  @ApiOperation({ summary: 'Update business descriptors' })
  updateBusiness(@Body() dto: BusinessSettingsDto) {
    return this.service.updateBusiness(dto);
  }

  @Post('business/logo')
  @ApiOperation({ summary: 'Upload brand asset logo' })
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(FileInterceptor('file'))
  uploadLogo(@UploadedFile() file: any) {
    const logoUrl = file
      ? `/uploads/logos/${file.originalname}`
      : '/uploads/logos/logo.png';
    return this.service.uploadLogo(logoUrl);
  }

  @Get('notifications-config')
  @ApiOperation({ summary: 'Fetch email, push, and SMS global switches' })
  getNotificationsConfig() {
    return this.service.getNotificationsConfig();
  }

  @Put('notifications-config')
  @ApiOperation({ summary: 'Update global notification parameters' })
  updateNotificationsConfig(@Body() dto: NotificationsConfigDto) {
    return this.service.updateNotificationsConfig(dto);
  }

  @Get('localization')
  @ApiOperation({ summary: 'Fetch default timezones, languages, and currencies' })
  getLocalization() {
    return this.service.getLocalization();
  }

  @Put('localization')
  @ApiOperation({ summary: 'Update default timezone & translations' })
  updateLocalization(@Body() dto: LocalizationDto) {
    return this.service.updateLocalization(dto);
  }

  @Get('data')
  @ApiOperation({ summary: 'Get platform auto-backup frequencies' })
  getData() {
    return this.service.getData();
  }

  @Put('data')
  @ApiOperation({ summary: 'Update data collection rules' })
  updateData(@Body() dto: DataSettingsDto) {
    return this.service.updateData(dto);
  }

  @Post('data/backup')
  @ApiOperation({ summary: 'Manually compile data backup' })
  backup() {
    return this.service.backup();
  }

  @Delete('data/cache')
  @ApiOperation({ summary: 'Clear server-side application cache' })
  clearCache() {
    return this.service.clearCache();
  }
}
