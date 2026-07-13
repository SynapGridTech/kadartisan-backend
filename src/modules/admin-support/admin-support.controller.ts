import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminSupportService } from './providers/admin-support.service';
import {
  CreateArticleDto,
  CreateFaqDto,
  FaqSearchQueryDto,
  KnowledgeSearchQueryDto,
  PublishFaqDto,
  ReplyTicketDto,
  TicketQueryDto,
  UpdateArticleDto,
  UpdateTicketStatusDto,
} from './dto/admin-support.dto';

// ================= FAQs =================
@ApiTags('Admin FAQs')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('faqs')
export class AdminFaqsController {
  constructor(private readonly service: AdminSupportService) {}

  @Get()
  @ApiOperation({ summary: 'Search all user FAQs' })
  list(@Query() query: FaqSearchQueryDto) {
    return this.service.listFaqs(query);
  }

  @Post()
  @ApiOperation({ summary: 'Publish new FAQ item' })
  create(@Body() dto: CreateFaqDto) {
    return this.service.createFaq(dto);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Retrieve FAQ statistics' })
  stats() {
    return this.service.faqStats();
  }

  @Put(':id')
  @ApiOperation({ summary: 'Edit active FAQ answers' })
  @ApiParam({ name: 'id', type: 'string' })
  update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: CreateFaqDto) {
    return this.service.updateFaq(id, dto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete FAQ entry' })
  @ApiParam({ name: 'id', type: 'string' })
  remove(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.deleteFaq(id);
  }

  @Put(':id/publish')
  @ApiOperation({ summary: 'Toggle FAQ visibility status' })
  @ApiParam({ name: 'id', type: 'string' })
  publish(@Param('id', ParseUUIDPipe) id: string, @Body() dto: PublishFaqDto) {
    return this.service.publishFaq(id, dto.published);
  }
}

// ================= knowledge base =================
@ApiTags('Admin FAQs')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('knowledge-base')
export class AdminKnowledgeBaseController {
  constructor(private readonly service: AdminSupportService) {}

  @Get()
  @ApiOperation({ summary: 'Retrieve internal help articles' })
  list(@Query() query: KnowledgeSearchQueryDto) {
    return this.service.listArticles(query);
  }

  @Post()
  @ApiOperation({ summary: 'Add new documentation article' })
  create(@Body() dto: CreateArticleDto) {
    return this.service.createArticle(dto);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Edit documentation article' })
  @ApiParam({ name: 'id', type: 'string' })
  update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateArticleDto) {
    return this.service.updateArticle(id, dto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete documentation article' })
  @ApiParam({ name: 'id', type: 'string' })
  remove(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.deleteArticle(id);
  }
}

// ================= support tickets =================
@ApiTags('Admin Support Tickets')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('support-tickets')
export class AdminSupportTicketsController {
  constructor(private readonly service: AdminSupportService) {}

  @Get()
  @ApiOperation({ summary: 'List client support tickets' })
  list(@Query() query: TicketQueryDto) {
    return this.service.listTickets(query);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Fetch full ticket messages history' })
  @ApiParam({ name: 'id', type: 'string' })
  getTicket(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getTicket(id);
  }

  @Put(':id/status')
  @ApiOperation({ summary: 'Update ticket status' })
  @ApiParam({ name: 'id', type: 'string' })
  updateStatus(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateTicketStatusDto) {
    return this.service.updateStatus(id, dto.status);
  }

  @Post(':id/reply')
  @ApiOperation({ summary: 'Send message reply to ticket' })
  @ApiParam({ name: 'id', type: 'string' })
  reply(@Param('id', ParseUUIDPipe) id: string, @Body() dto: ReplyTicketDto) {
    return this.service.reply(id, dto.message);
  }
}
