import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { PinoLogger } from 'nestjs-pino';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(private readonly logger: PinoLogger) {}

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();

    const isHttp = exception instanceof HttpException;
    const status = isHttp ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    const message = isHttp ? (exception as HttpException).message : 'Internal server error';

    // Log full exception object
    this.logger.error(
      {
        url: req.originalUrl,
        method: req.method,
        status,
        err: exception,
      },
      'Unhandled exception',
    );

    const payload = {
      statusCode: status,
      message,
      path: req.originalUrl,
      timestamp: new Date().toISOString(),
    };

    res.status(status).json(payload);
  }
}