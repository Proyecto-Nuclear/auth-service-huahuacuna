import { PrismaClient, Role, UserStatus } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Iniciando seeding de la base de datos...');

  // Hashear la contraseña del super admin
  const password = 'SuperAdmin123';
  const hashedPassword = await bcrypt.hash(password, 10);

  // Crear el super admin
  const superAdmin = await prisma.user.upsert({
    where: { email: 'super@fundacion.org' },
    update: {},
    create: {
      email: 'super@fundacion.org',
      name: 'Super Administrador',
      password: hashedPassword,
      role: Role.SUPER_ADMIN,
      status: UserStatus.ACTIVE,
      emailVerified: true,
      phone: '+51999888777',
      documentId: '12345678',
      address: 'Oficina Central de la Fundación',
    },
  });

  console.log('✅ Super Admin creado:');
  console.log({
    id: superAdmin.id,
    email: superAdmin.email,
    name: superAdmin.name,
    role: superAdmin.role,
  });
  console.log('\n📝 Credenciales:');
  console.log('Email: super@fundacion.org');
  console.log('Password: SuperAdmin123');
  console.log('\n🎉 Seeding completado exitosamente!');
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error('❌ Error durante el seeding:', e);
    await prisma.$disconnect();
    process.exit(1);
  });
