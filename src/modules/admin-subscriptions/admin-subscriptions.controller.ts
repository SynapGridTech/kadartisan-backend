import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminSubscriptionsService } from './providers/admin-subscriptions.service';
import {
  AssignPlanDto,
  CancelSubscriptionDto,
  ChangePlanDto,
  CreatePlanDto,
  ExtendSubscriptionDto,
  ListSubscriptionsQueryDto,
  SubscriptionNoteDto,
  UpdatePlanDto,
  WaivePaymentDto,
} from './dto/admin-subscriptions.dto';

// ================= 12.1 plans =================
@ApiTags('Admin Subscription Plans')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/subscription-plans')
export class AdminSubscriptionPlansController {
  constructor(private readonly service: AdminSubscriptionsService) {}

  @Get()
  @ApiOperation({ summary: 'Fetch available plans' })
  list() {
    return this.service.listPlans();
  }

  @Get('summary')
  @ApiOperation({ summary: 'Plans performance metrics' })
  summary() {
    return this.service.plansSummary();
  }

  @Get(':planId')
  @ApiOperation({ summary: 'Fetch detail of a plan' })
  @ApiParam({ name: 'planId', type: 'string' })
  getPlan(@Param('planId', ParseUUIDPipe) planId: string) {
    return this.service.getPlan(planId);
  }

  @Post()
  @ApiOperation({ summary: 'Create new pricing/limits tier' })
  create(@Body() dto: CreatePlanDto) {
    return this.service.createPlan(dto);
  }

  @Put(':planId')
  @ApiOperation({ summary: 'Update pricing features / rates' })
  @ApiParam({ name: 'planId', type: 'string' })
  update(@Param('planId', ParseUUIDPipe) planId: string, @Body() dto: UpdatePlanDto) {
    return this.service.updatePlan(planId, dto);
  }

  @Post(':planId/archive')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Archive plan (no new signups)' })
  @ApiParam({ name: 'planId', type: 'string' })
  archive(@Param('planId', ParseUUIDPipe) planId: string) {
    return this.service.archivePlan(planId);
  }

  @Post(':planId/duplicate')
  @ApiOperation({ summary: 'Clone plan configuration' })
  @ApiParam({ name: 'planId', type: 'string' })
  duplicate(@Param('planId', ParseUUIDPipe) planId: string) {
    return this.service.duplicatePlan(planId);
  }
}

// ================= 12.2 subscribers =================
@ApiTags('Admin Subscriptions')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/subscriptions')
export class AdminSubscriptionsController {
  constructor(private readonly service: AdminSubscriptionsService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated subscribers list' })
  list(@Query() query: ListSubscriptionsQueryDto) {
    return this.service.listSubscriptions(query);
  }

  @Get('summary')
  @ApiOperation({ summary: 'Subscription metrics (churn, expiration)' })
  summary() {
    return this.service.subscriptionsSummary();
  }

  @Get(':subId')
  @ApiOperation({ summary: 'Fetch single subscriber record details' })
  @ApiParam({ name: 'subId', type: 'string' })
  getSubscription(@Param('subId', ParseUUIDPipe) subId: string) {
    return this.service.getSubscription(subId);
  }

  @Post(':subId/change-plan')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Change artisan subscription tier (idempotent)' })
  @ApiParam({ name: 'subId', type: 'string' })
  changePlan(@Param('subId', ParseUUIDPipe) subId: string, @Body() dto: ChangePlanDto) {
    return this.service.changePlan(subId, dto);
  }

  @Post(':subId/cancel')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Cancel subscription (immediate/renewal)' })
  @ApiParam({ name: 'subId', type: 'string' })
  cancel(@Param('subId', ParseUUIDPipe) subId: string, @Body() dto: CancelSubscriptionDto) {
    return this.service.cancel(subId, dto);
  }

  @Post(':subId/extend')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Apply complimentary days extension' })
  @ApiParam({ name: 'subId', type: 'string' })
  extend(@Param('subId', ParseUUIDPipe) subId: string, @Body() dto: ExtendSubscriptionDto) {
    return this.service.extend(subId, dto);
  }

  @Post(':subId/waive')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Waive a monthly renewal fee invoice' })
  @ApiParam({ name: 'subId', type: 'string' })
  waive(@Param('subId', ParseUUIDPipe) subId: string, @Body() dto: WaivePaymentDto) {
    return this.service.waive(subId, dto);
  }

  @Post(':subId/notes')
  @ApiOperation({ summary: 'Add admin operational note' })
  @ApiParam({ name: 'subId', type: 'string' })
  addNote(
    @Param('subId', ParseUUIDPipe) subId: string,
    @Body() dto: SubscriptionNoteDto,
    @Req() req: any,
  ) {
    return this.service.addNote(subId, dto.content, req.user?.id);
  }
}

// ================= user-scoped =================
@ApiTags('Admin Subscriptions')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('api/admin/users')
export class AdminUserSubscriptionController {
  constructor(private readonly service: AdminSubscriptionsService) {}

  @Get(':userId/subscription')
  @ApiOperation({ summary: 'Query subscription details for a specific user' })
  @ApiParam({ name: 'userId', type: 'string' })
  getUserSubscription(@Param('userId', ParseUUIDPipe) userId: string) {
    return this.service.getUserSubscription(userId);
  }

  @Post(':userId/subscription/assign')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Force assignment of a plan to a user' })
  @ApiParam({ name: 'userId', type: 'string' })
  assignPlan(@Param('userId', ParseUUIDPipe) userId: string, @Body() dto: AssignPlanDto) {
    return this.service.assignPlan(userId, dto);
  }
}
