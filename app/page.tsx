'use client';

import { Card } from 'antd';
import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card title="Welcome to NextJS Starter">
        <p>NextJS Starter Template is a modern and scalable system for your business.</p>
        <div className="mt-4">
          <Link href={'/dashboard'}>Go to Dashboard</Link>
        </div>
      </Card>
    </div>
  );
}
