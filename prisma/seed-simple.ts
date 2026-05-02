import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import 'dotenv/config';

async function main() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  });

  const adapter = new PrismaPg(pool);
  const prisma = new PrismaClient({ adapter });
  
  console.log('🌱 Starting seed...');

  const skills = [
    { name: 'Plumbing', category: 'Construction' },
    { name: 'Carpentry', category: 'Construction' },
    { name: 'Electrical Installation', category: 'Electrical' },
    { name: 'Bricklaying', category: 'Construction' },
    { name: 'Painting', category: 'Construction' },
    { name: 'Welding', category: 'Construction' },
    { name: 'Tiling', category: 'Construction' },
    { name: 'Tailoring', category: 'Fashion' },
    { name: 'Hairdressing', category: 'Beauty' },
    { name: 'Phone Repair', category: 'Technology' },
  ];

  console.log('📋 Seeding skills...');
  for (const skill of skills) {
    await prisma.skill.upsert({
      where: { name: skill.name },
      update: {},
      create: skill,
    });
  }
  
  console.log(`✅ Seeded ${skills.length} skills`);
  await prisma.$disconnect();
}

main().catch(console.error);
