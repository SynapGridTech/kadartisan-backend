import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

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
  { name: 'Solar Panel Installation', category: 'Electrical' },
  { name: 'Inverter Installation', category: 'Electrical' },
  { name: 'Air Conditioner Repair', category: 'Electrical' },
  { name: 'Generator Repair', category: 'Electrical' },

  // Automotive
  { name: 'Mechanic (Auto)', category: 'Automotive' },
  { name: 'Auto Electrician', category: 'Automotive' },
  { name: 'Panel Beating', category: 'Automotive' },
  { name: 'Vehicle Painting', category: 'Automotive' },
  { name: 'Tire Services', category: 'Automotive' },

  // Home & Kitchen
  { name: 'Furniture Making', category: 'Home & Kitchen' },
  { name: 'Upholstery', category: 'Home & Kitchen' },
  { name: 'Aluminum Fabrication', category: 'Home & Kitchen' },
  { name: 'Glass Works', category: 'Home & Kitchen' },
  { name: 'Curtain Making', category: 'Home & Kitchen' },

  // Fashion & Textile
  { name: 'Tailoring', category: 'Fashion' },
  { name: 'Fashion Design', category: 'Fashion' },
  { name: 'Shoe Making', category: 'Fashion' },
  { name: 'Embroidery', category: 'Fashion' },
  { name: 'Knitting', category: 'Fashion' },

  // Beauty & Personal Care
  { name: 'Hairdressing', category: 'Beauty' },
  { name: 'Barbing', category: 'Beauty' },
  { name: 'Makeup Artistry', category: 'Beauty' },
  { name: 'Nail Technician', category: 'Beauty' },

  // Technology
  { name: 'Phone Repair', category: 'Technology' },
  { name: 'Computer Repair', category: 'Technology' },
  { name: 'Network Installation', category: 'Technology' },
  { name: 'CCTV Installation', category: 'Technology' },

  // Agriculture
  { name: 'Farming', category: 'Agriculture' },
  { name: 'Animal Husbandry', category: 'Agriculture' },
  { name: 'Irrigation Systems', category: 'Agriculture' },

  // Metal Works
  { name: 'Blacksmithing', category: 'Metal Works' },
  { name: 'Gate Making', category: 'Metal Works' },
  { name: 'Railing Fabrication', category: 'Metal Works' },

  // Miscellaneous
  { name: 'Masonry', category: 'Construction' },
  { name: 'Cleaning Services', category: 'Services' },
  { name: 'Moving & Hauling', category: 'Services' },
  { name: 'Gardening & Landscaping', category: 'Services' },
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
  },
  {
    state: 'Kano',
    lgas: [
      'Kano Municipal',
      'Dala',
      'Gwale',
      'Nassarawa',
      'Tarauni',
      'Fagge',
      'Kumbotso',
      'Ungogo',
      'Bichi',
      'Rano',
      'Wudil',
      'Gwarzo',
    ],
  },
 
  {
    state: 'Bauchi',
    lgas: [
      'Bauchi',
      'Tafawa Balewa',
      'Dass',
      'Toro',
      'Ningi',
      'Warji',
      'Katagum',
      'Misau',
      'Azare',
    ],
  },
];

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
