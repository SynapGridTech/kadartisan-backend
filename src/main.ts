import { setDefaultResultOrder } from 'node:dns';
// Prefer IPv4 for all DNS lookups. Some hosts (e.g. Railway) resolve AAAA
// records for external services like smtp.gmail.com but have no working
// outbound IPv6 route, which surfaces as `connect ENETUNREACH ...::587`.
// Resolving IPv4 first avoids attempting the unreachable IPv6 address.
setDefaultResultOrder('ipv4first');

import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Logger } from 'nestjs-pino';
import { RolesGuard } from './common/guards/roles.guard';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(Logger));

  const configService = app.get(ConfigService);
  const frontendUrl = configService.get<string>('frontendUrl') ?? 'http://localhost:3002';
  const allowedOrigins = frontendUrl.split(',').map((o) => o.trim());

  app.enableCors({
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  });

  // Global validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  //  SWAGGER SETUP
  const config = new DocumentBuilder()
    .setTitle('KadArtisan API')
    .setDescription('API documentation for the KadArtisan backend')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true, // keep bearer token active
    },
  });
  // ------------------------------------------

  const port = process.env.PORT ?? 3002;
  await app.listen(port);
  console.log('Swagger is running on http://localhost:3002/docs');
}
bootstrap();
