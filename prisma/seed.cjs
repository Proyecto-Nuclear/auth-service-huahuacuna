const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  // Optional: Guard against running in production
  if (process.env.NODE_ENV === 'production') {
    console.log('⚠️  Seed script is not meant for production environments. Skipping.');
    return;
  }

  console.log('🌱 Starting database seeding...');

  // Hash passwords with 10 salt rounds
  const adminPassword = await bcrypt.hash('Admin123!', 10);
  const padrinoPassword = await bcrypt.hash('Padrino123!', 10);

  // Upsert ADMIN user
  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@huahuacuna.test' },
    update: {
      password: adminPassword,
      name: 'Admin Huahuacuna',
      role: 'ADMIN',
      status: 'ACTIVE',
      emailVerified: true,
    },
    create: {
      email: 'admin@huahuacuna.test',
      password: adminPassword,
      name: 'Admin Huahuacuna',
      role: 'ADMIN',
      status: 'ACTIVE',
      emailVerified: true,
    },
  });

  console.log('✅ ADMIN user created/updated:');
  console.log(`   Email: ${adminUser.email}`);
  console.log(`   Name: ${adminUser.name}`);
  console.log(`   Role: ${adminUser.role}`);

  // Upsert PADRINO user
  const padrinoUser = await prisma.user.upsert({
    where: { email: 'padrino@huahuacuna.test' },
    update: {
      password: padrinoPassword,
      name: 'Padrino Demo',
      role: 'PADRINO',
      status: 'ACTIVE',
      emailVerified: true,
    },
    create: {
      email: 'padrino@huahuacuna.test',
      password: padrinoPassword,
      name: 'Padrino Demo',
      role: 'PADRINO',
      status: 'ACTIVE',
      emailVerified: true,
    },
  });

  console.log('✅ PADRINO user created/updated:');
  console.log(`   Email: ${padrinoUser.email}`);
  console.log(`   Name: ${padrinoUser.name}`);
  console.log(`   Role: ${padrinoUser.role}`);

  console.log('\n📝 Login Credentials (for local/dev only):');
  console.log('─────────────────────────────────────────');
  console.log('ADMIN:');
  console.log('  Email: admin@huahuacuna.test');
  console.log('  Password: Admin123!');
  console.log('\nPADRINO:');
  console.log('  Email: padrino@huahuacuna.test');
  console.log('  Password: Padrino123!');
  console.log('─────────────────────────────────────────');
  console.log('🎉 Seeding completed successfully!');
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error('❌ Error during seeding:', e);
    await prisma.$disconnect();
    process.exit(1);
  });
