import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class User {
  @ApiProperty({ example: 'uuid-value' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ example: 'ahmad dogo' })
  @Column()
  fullName: string;

  @ApiProperty({ example: '+2349063801889' })
  @Column({ unique: true })
  phoneNumber: string;

  @ApiProperty({ example: 'ahmadogo@email.com', required: false })
  @Column({ unique: true, nullable: true })
  email?: string;

  @Column()
  password: string;

  @ApiProperty({ example: true })
  @Column({ default: true })
  isVerified: boolean;

  @ApiProperty()
  @CreateDateColumn()
  createdAt: Date;
}
