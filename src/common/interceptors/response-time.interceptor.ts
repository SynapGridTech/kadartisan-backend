import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { PinoLogger } from 'nestjs-pino';

@Injectable()
export class ResponseTimeInterceptor implements NestInterceptor {
  constructor(private readonly logger: PinoLogger) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const started = Date.now();
    return next.handle().pipe(
      tap(() => {
        const ctx = context.switchToHttp();
        const req = ctx.getRequest<Request>() as any;
        const res = ctx.getResponse<Response>() as any;
        const ms = Date.now() - started;
        this.logger.debug({ url: (req as any).originalUrl, status: (res as any).statusCode, ms }, 'Handled request');
      }),
    );
  }
}