import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import knex from '@/knex';
import { requirePermission } from '@/lib/auth/server-permissions';

export async function GET() {
  const session = await getServerSession(authOptions);

  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  await requirePermission('security_log', 'view');

  try {
    // Fetch security logs with Knex
    const logs = await knex('SecurityLog')
      .select(
        'SecurityLog.id',
        'SecurityLog.userId',
        'SecurityLog.email',
        'SecurityLog.ipAddress',
        'SecurityLog.userAgent',
        'SecurityLog.status',
        'SecurityLog.type',
        'SecurityLog.message',
        'SecurityLog.createdAt'
      )
      .orderBy('SecurityLog.createdAt', 'desc');

    // For each log, get user information if userId exists
    for (const log of logs) {
      if (log.userId) {
        const user = await knex('User')
          .where({ id: log.userId })
          .select('firstName', 'lastName')
          .first();
        
        log.user = user || null;
      } else {
        log.user = null;
      }
    }

    return NextResponse.json(logs);
  } catch (error) {
    console.error('Failed to fetch security logs:', error);
    return NextResponse.json({ error: 'Failed to fetch security logs' }, { status: 500 });
  }
}
