import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { prisma } from '@/lib/prisma';
import { requirePermission } from '@/lib/auth/permissions';

export async function GET() {
  const session = await getServerSession(authOptions);

  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  await requirePermission('security_log', 'view');

  try {
    const logs = await prisma.securityLog.findMany({
      orderBy: {
        createdAt: 'desc',
      },
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
      },
    });

    return NextResponse.json(logs);
  } catch (error) {
    console.error('Failed to fetch security logs:', error);
    return NextResponse.json({ error: 'Failed to fetch security logs' }, { status: 500 });
  }
}
