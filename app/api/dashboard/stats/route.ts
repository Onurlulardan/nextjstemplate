import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import knex from '@/knex';

export async function GET() {
  try {
    // Check authentication
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Get total organizations count
    const [orgCount] = await knex('Organization').count('* as count');
    const totalOrganizations = parseInt(orgCount.count as string, 10);

    // Get users statistics
    const [userCount] = await knex('User').count('* as count');
    const totalUsers = parseInt(userCount.count as string, 10);
    
    const [activeUserCount] = await knex('User')
      .where({ status: 'ACTIVE' })
      .count('* as count');
    const activeUsers = parseInt(activeUserCount.count as string, 10);

    return NextResponse.json({
      totalOrganizations,
      totalUsers,
      activeUsers,
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
