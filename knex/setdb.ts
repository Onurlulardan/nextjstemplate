import 'dotenv/config';
import knex from './index.js';

async function main() {
  // Mevcut tabloları silme
  console.log('Mevcut tabloları silme işlemi başlatılıyor...');
  try {
    await knex.schema.dropTableIfExists('SecurityLog');
    await knex.schema.dropTableIfExists('OrganizationMember');
    await knex.schema.dropTableIfExists('UserRole');
    await knex.schema.dropTableIfExists('PermissionAction');
    await knex.schema.dropTableIfExists('Permission');
    await knex.schema.dropTableIfExists('Role');
    await knex.schema.dropTableIfExists('Organization');
    await knex.schema.dropTableIfExists('VerificationToken');
    await knex.schema.dropTableIfExists('Session');
    await knex.schema.dropTableIfExists('Account');
    await knex.schema.dropTableIfExists('User');
    await knex.schema.dropTableIfExists('Action');
    await knex.schema.dropTableIfExists('Resource');
    console.log('Mevcut tablolar başarıyla silindi.');
    
    // Enum tiplerini silme
    console.log('Enum tiplerini silme işlemi başlatılıyor...');
    await knex.raw('DROP TYPE IF EXISTS "PermissionTarget"');
    console.log('Enum tipleri başarıyla silindi.');
    
    // UUID eklentisini yükleme
    console.log('UUID eklentisi yükleniyor...');
    await knex.raw('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    await knex.raw('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
    console.log('UUID eklentileri başarıyla yüklendi.');
  } catch (err) {
    console.error('Tabloları, enum tiplerini veya eklentileri yüklerken hata oluştu:', err);
  }

  // Yeni tabloları oluşturma
  // Resource Table
  await knex.schema.createTable('Resource', (table) => {
    table.string('id').primary();
    table.string('name').notNullable();
    table.string('slug').notNullable().unique().index();
    table.string('description');
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
  });

  // Action Table
  await knex.schema.createTable('Action', (table) => {
    table.string('id').primary();
    table.string('name').notNullable();
    table.string('slug').notNullable().unique().index();
    table.string('description');
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
  });

  // User Table
  await knex.schema.createTable('User', (table) => {
    table.string('id').primary();
    table.string('email').notNullable().unique();
    table.string('password').notNullable();
    table.string('firstName');
    table.string('lastName');
    table.string('phone');
    table.string('avatar');
    table.string('status').notNullable().defaultTo('ACTIVE');
    table.boolean('emailVerified').notNullable().defaultTo(false);
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
  });

  // Account Table (NextAuth)
  await knex.schema.createTable('Account', (table) => {
    table.string('userId').notNullable().references('User.id').onDelete('CASCADE');
    table.string('type').notNullable();
    table.string('provider').notNullable();
    table.string('providerAccountId').notNullable();
    table.string('refresh_token');
    table.string('access_token');
    table.bigInteger('expires_at');
    table.string('token_type');
    table.string('scope');
    table.string('id_token');
    table.string('session_state');
    table.string('oauth_token_secret');
    table.string('oauth_token');
    table.primary(['provider', 'providerAccountId']);
    table.index(['userId']);
  });

  // Session Table (NextAuth)
  await knex.schema.createTable('Session', (table) => {
    table.string('sessionToken').primary();
    table.string('userId').notNullable().references('User.id').onDelete('CASCADE');
    table.timestamp('expires').notNullable();
    table.index(['userId']);
  });

  // VerificationToken Table (NextAuth)
  await knex.schema.createTable('VerificationToken', (table) => {
    table.string('identifier').notNullable();
    table.string('token').notNullable();
    table.timestamp('expires').notNullable();
    table.primary(['identifier', 'token']);
  });

  // Organization Table
  await knex.schema.createTable('Organization', (table) => {
    table.string('id').primary();
    table.string('name').notNullable();
    table.string('slug').notNullable().unique();
    table.string('status').notNullable().defaultTo('ACTIVE');
    table.string('ownerId').notNullable();
    table.string('parentId');
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    table.index(['ownerId']);
    table.index(['parentId']);
    table.foreign('ownerId').references('User.id').onDelete('RESTRICT');
    table.foreign('parentId').references('Organization.id').onDelete('CASCADE');
  });

  // Role Table
  await knex.schema.createTable('Role', (table) => {
    table.string('id').primary();
    table.string('name').notNullable().unique();
    table.string('description');
    table.boolean('isDefault').notNullable().defaultTo(false);
    table.string('organizationId');
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    table.index(['organizationId']);
    table.foreign('organizationId').references('Organization.id').onDelete('CASCADE');
  });

  // Permission Table
  await knex.schema.createTable('Permission', (table) => {
    table.string('id').primary();
    table.string('resourceId').notNullable();
    table.enu('target', ['USER', 'ROLE', 'ORGANIZATION'], { useNative: true, enumName: 'PermissionTarget' }).notNullable();
    table.string('userId');
    table.string('roleId');
    table.string('organizationId');
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    table.index(['userId']);
    table.index(['roleId']);
    table.index(['organizationId']);
    table.foreign('resourceId').references('Resource.id').onDelete('CASCADE');
    table.foreign('userId').references('User.id').onDelete('CASCADE');
    table.foreign('roleId').references('Role.id').onDelete('CASCADE');
    table.foreign('organizationId').references('Organization.id').onDelete('CASCADE');
  });

  // PermissionAction Table
  await knex.schema.createTable('PermissionAction', (table) => {
    table.string('id').primary();
    table.string('permissionId').notNullable();
    table.string('actionId').notNullable();
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    table.unique(['permissionId', 'actionId']);
    table.index(['permissionId']);
    table.index(['actionId']);
    table.foreign('permissionId').references('Permission.id').onDelete('CASCADE');
    table.foreign('actionId').references('Action.id').onDelete('CASCADE');
  });

  // UserRole Table
  await knex.schema.createTable('UserRole', (table) => {
    table.string('id').primary();
    table.string('userId').notNullable();
    table.string('roleId').notNullable();
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    table.unique(['userId', 'roleId']);
    table.index(['userId']);
    table.index(['roleId']);
    table.foreign('userId').references('User.id').onDelete('CASCADE');
    table.foreign('roleId').references('Role.id').onDelete('CASCADE');
  });

  // OrganizationMember Table
  await knex.schema.createTable('OrganizationMember', (table) => {
    table.string('id').primary();
    table.string('organizationId').notNullable();
    table.string('userId').notNullable();
    table.string('roleId');
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    table.unique(['organizationId', 'userId']);
    table.index(['userId']);
    table.index(['organizationId']);
    table.index(['roleId']);
    table.foreign('organizationId').references('Organization.id').onDelete('CASCADE');
    table.foreign('userId').references('User.id').onDelete('CASCADE');
    table.foreign('roleId').references('Role.id').onDelete('CASCADE');
  });

  // SecurityLog Table
  await knex.schema.createTable('SecurityLog', (table) => {
    table.string('id').primary();
    table.string('userId');
    table.string('email').notNullable();
    table.string('ipAddress').notNullable();
    table.string('userAgent').notNullable();
    table.string('status').notNullable();
    table.string('type').notNullable();
    table.string('message').notNullable();
    table.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    table.index(['userId']);
    table.index(['createdAt']);
    table.index(['status']);
    table.foreign('userId').references('User.id').onDelete('SET NULL');
  });
}

main()
  .then(() => { console.log('Tüm tablolar başarıyla oluşturuldu!'); process.exit(0); })
  .catch((err) => { console.error('Hata:', err); process.exit(1); });
