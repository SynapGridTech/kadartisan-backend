import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class Otp {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ example: '+2349063801889' })
  @Column()
  identifier: string;

  @Column()
  code: string;

  @ApiProperty()
  @Column()
  expiresAt: Date;

  @Column({ default: false })
  isUsed: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
