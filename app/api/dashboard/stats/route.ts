import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { prisma } from '@/lib/prisma';

export async function GET() {
  try {
    // Check authentication
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Get total organizations count
    const totalOrganizations = await prisma.organization.count();

    // Get users statistics
    const totalUsers = await prisma.user.count();
    const activeUsers = await prisma.user.count({
      where: {
        status: 'ACTIVE',
      },
    });

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
