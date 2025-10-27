import { NestFactory } from "@nestjs/core";
import { Logger, ValidationPipe } from "@nestjs/common";
import { EnvsConfig } from "./config/env.config.js";
import AppModule from "./app.module.js";
import { MicroserviceOptions, Transport } from "@nestjs/microservices";
import { Partitioners } from "kafkajs";

const logger = new Logger('Auth Service');

const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule,
  {
  transport: Transport.KAFKA,
  options: {
    client: {
      brokers: [EnvsConfig.KAFKA_BROKER],
    },
    consumer: {
      groupId:'auth-consumer',
    },
    producer: {
      createPartitioner: Partitioners.DefaultPartitioner
    }
  }
});

app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
  }),
);

await app.listen();
logger.log(`Auth Microservice running on port ${EnvsConfig.PORT}`);