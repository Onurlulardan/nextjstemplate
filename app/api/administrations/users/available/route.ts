import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/users/available
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'view');

    const users = await knex('User')
      .where({ status: 'ACTIVE' })
      .select(
        'id',
        'email',
        'firstName',
        'lastName'
      )
      .orderBy('firstName', 'asc');

    return NextResponse.json(users);
  } catch (error) {
    console.error('[USERS_AVAILABLE_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
