import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { UsersService } from './providers/user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UsersService) {}
}
