import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { PrismaClient } from "@prisma/client";

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {

  private readonly LOGGER = new Logger('PrismaService');

  async onModuleDestroy() {
    await this.$disconnect();
    this.LOGGER.warn('PrismaService disconnected from the database');
  }

  async onModuleInit() {
    await this.$connect();
    this.LOGGER.log('PrismaService connected to the database');
  }

}