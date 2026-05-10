import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import * as bcrypt from 'bcrypt';
import 'dotenv/config';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

// Default admin credentials (overridable via .env)
const defaultAdmin = {
  email: process.env.ADMIN_EMAIL,
  password: process.env.ADMIN_PASSWORD,
  fullName: process.env.ADMIN_FULL_NAME, 
  phoneNumber: process.env.ADMIN_PHONE 
};

// Nigerian artisan skills organized by category
const skills = [
  // Construction & Building
  { name: 'Bricklaying', category: 'Construction' },
  { name: 'Plastering', category: 'Construction' },
  { name: 'Carpentry', category: 'Construction' },
  { name: 'Roofing', category: 'Construction' },
  { name: 'Painting', category: 'Construction' },
  { name: 'Welding', category: 'Construction' },
  { name: 'Iron Bending', category: 'Construction' },
  { name: 'POP Installation', category: 'Construction' },
  { name: 'Tiling', category: 'Construction' },
  { name: 'Plumbing', category: 'Construction' },

  // Electrical & Electronics
  { name: 'Electrical Installation', category: 'Electrical' },
  { name: 'Electrical Repair', category: 'Electrical' },

  // Automotive
  { name: 'Mechanic (Auto)', category: 'Automotive' },

  // Fashion & Textile
  { name: 'Tailoring', category: 'Fashion' },
  { name: 'Fashion Design', category: 'Fashion' },
  { name: 'Shoe Making', category: 'Fashion' },


  // Beauty & Personal Care
  { name: 'Hairdressing', category: 'Beauty' },
  { name: 'Barbing', category: 'Beauty' },
  { name: 'Makeup Artistry', category: 'Beauty' },

  // Technology
  { name: 'Phone Repair', category: 'Technology' },
  { name: 'Computer Repair', category: 'Technology' },
  { name: 'Network Installation', category: 'Technology' },
  { name: 'CCTV Installation', category: 'Technology' },

  // Agriculture
  { name: 'Farming', category: 'Agriculture' },
  { name: 'Animal Husbandry', category: 'Agriculture' },

  // Metal Works
  { name: 'Blacksmithing', category: 'Metal Works' },

  // Miscellaneous
  { name: 'Cleaning Services', category: 'Services' },
 
];

// Nigerian States with sample LGAs (focusing on major states)
const nigerianLocations = [
  {
    state: 'Kaduna',
    lgas: [
      'Kaduna North',
      'Kaduna South',
      'Chikun',
      'Igabi',
      'Zaria',
      'Kajuru',
      'Kaura',
      'Jaba',
      'Sanga',
      'Kachia',
      'Makarfi',
      'Sabon Gari',
      'Kubau',
      'Birnin Gwari',
    ],
  }
];

async function seedAdmin() {
  console.log('👤 Seeding default admin...');

  // Validate required env vars up-front
  const missing = (
    ['ADMIN_EMAIL', 'ADMIN_PASSWORD', 'ADMIN_FULL_NAME', 'ADMIN_PHONE'] as const
  ).filter((k) => !process.env[k]);
  if (missing.length > 0) {
    throw new Error(
      `Admin seeding skipped — missing required env var(s): ${missing.join(', ')}`,
    );
  }

  const email = defaultAdmin.email as string;
  const password = defaultAdmin.password as string;
  const fullName = defaultAdmin.fullName as string;
  const phoneNumber = defaultAdmin.phoneNumber as string;

  const existing = await prisma.user.findFirst({
    where: { role: 'ADMIN' },
    include: { adminProfile: true },
  });

  if (existing) {
    console.log(`ℹ️  Admin already exists (${existing.email}). Skipping creation.`);
    if (!existing.adminProfile) {
      await prisma.adminProfile.create({ data: { userId: existing.id } });
      console.log('🔧 Created missing AdminProfile for existing admin.');
    }
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await prisma.$transaction(async (tx) => {
    const adminUser = await tx.user.create({
      data: {
        email,
        phoneNumber,
        fullName,
        password: hashedPassword,
        role: 'ADMIN',
        isVerified: true,
      },
    });
    await tx.adminProfile.create({ data: { userId: adminUser.id } });
  });

  console.log(`✅ Default admin created: ${email}`);
  console.log('   ⚠️  Change the default password via POST /auth/request-password-reset');
}

async function main() {
  console.log('🌱 Starting seed...');

  // Seed Skills
  console.log('📋 Seeding skills...');
  for (const skill of skills) {
    await prisma.skill.upsert({
      where: { name: skill.name },
      update: {},
      create: skill,
    });
  }
  console.log(`✅ Seeded ${skills.length} skills`);

  // Seed default admin
  await seedAdmin();

  // Seed Locations (we'll store these as JSON in the app, not in DB)
  // The LGA data will be used by the frontend for dropdowns
  console.log(`📍 Location data prepared for ${nigerianLocations.length} states`);
  console.log('   (Location data will be served via API endpoint)');

  console.log('🎉 Seed completed successfully!');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

// Export locations for API endpoint
export { nigerianLocations };
