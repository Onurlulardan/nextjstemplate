import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import knex from '@/knex';

export async function POST(req: Request) {
  try {
    const { email, password, firstName, lastName, phone } = await req.json();

    // Check if user already exists
    const existingUser = await knex('User')
      .where({ email })
      .first();

    if (existingUser) {
      return new NextResponse('Email already exists', { status: 400 });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Use a transaction for creating user and assigning default role
    const result = await knex.transaction(async (trx) => {
      // 1. Create the user
      const insertResult = await trx('User')
        .insert({
          id: trx.raw('uuid_generate_v4()'),
          email,
          password: hashedPassword,
          firstName,
          lastName,
          phone,
          status: 'ACTIVE', // Default status
          createdAt: trx.fn.now(),
          updatedAt: trx.fn.now()
        })
        .returning('id');
      
      // Extract the user ID as a string
      const userId = insertResult[0].id;

      // 2. Find default role
      const defaultRole = await trx('Role')
        .where({ isDefault: true })
        .first();

      // 3. If default role exists, assign it to the user
      if (defaultRole) {
        await trx('UserRole')
          .insert({
            id: trx.raw('uuid_generate_v4()'),
            userId: userId,
            roleId: defaultRole.id,
            createdAt: trx.fn.now(),
            updatedAt: trx.fn.now()
          });
      }

      // Get the created user
      const user = await trx('User')
        .where({ id: userId })
        .first();

      return { user, defaultRole };
    });

    return NextResponse.json({
      user: {
        email: result.user.email,
        firstName: result.user.firstName,
        lastName: result.user.lastName,
      },
      role: result.defaultRole
        ? {
            name: result.defaultRole.name,
            isDefault: result.defaultRole.isDefault,
          }
        : null,
    });
  } catch (error) {
    console.error('Registration error:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}
