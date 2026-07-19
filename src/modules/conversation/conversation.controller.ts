import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Param,
  Query,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
} from '@nestjs/swagger';
import { ConversationService } from './providers/conversation.service';
import { CreateConversationDto } from './dto/create-conversation.dto';
import { SendMessageDto } from './dto/send-message.dto';
import { GetRequestsQueryDto } from '../booking/dto/get-requests-query.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@ApiTags('Conversations')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('conversations')
export class ConversationController {
  constructor(private readonly conversationService: ConversationService) {}

  //__________ START OR GET A CONVERSATION ________________________
  @Post()
  @Roles(Role.USER, Role.ARTISAN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary:
      'Start a conversation with another user (idempotent); optionally send a first message',
  })
  public async createConversation(
    @Req() req: any,
    @Body() dto: CreateConversationDto,
  ) {
    return this.conversationService.createOrGetConversation(req.user.id, dto);
  }

  //__________ LIST MY CONVERSATIONS ________________________
  @Get()
  @Roles(Role.USER, Role.ARTISAN)
  @ApiOperation({ summary: "List the current user's conversations" })
  public async getConversations(
    @Req() req: any,
    @Query() query: GetRequestsQueryDto,
  ) {
    return this.conversationService.getConversations(req.user.id, query);
  }

  //__________ GET A SINGLE CONVERSATION ________________________
  @Get(':id')
  @Roles(Role.USER, Role.ARTISAN)
  @ApiOperation({ summary: 'Get a single conversation by id' })
  @ApiParam({
    name: 'id',
    description: 'Conversation id (UUID)',
    type: 'string',
  })
  public async getConversation(
    @Req() req: any,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.conversationService.getConversationById(req.user.id, id);
  }

  //__________ LIST MESSAGES IN A CONVERSATION ________________________
  @Get(':id/messages')
  @Roles(Role.USER, Role.ARTISAN)
  @ApiOperation({
    summary: 'List messages in a conversation (marks inbound messages as read)',
  })
  @ApiParam({
    name: 'id',
    description: 'Conversation id (UUID)',
    type: 'string',
  })
  public async getMessages(
    @Req() req: any,
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: GetRequestsQueryDto,
  ) {
    return this.conversationService.getMessages(req.user.id, id, query);
  }

  //__________ SEND A MESSAGE ________________________
  @Post(':id/messages')
  @Roles(Role.USER, Role.ARTISAN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Send a message into a conversation' })
  @ApiParam({
    name: 'id',
    description: 'Conversation id (UUID)',
    type: 'string',
  })
  public async sendMessage(
    @Req() req: any,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: SendMessageDto,
  ) {
    return this.conversationService.sendMessage(req.user.id, id, dto);
  }
}
