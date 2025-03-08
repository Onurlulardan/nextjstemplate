import { NextResponse, NextRequest } from 'next/server';
import { withAuth } from 'next-auth/middleware';

// First add request info to headers
async function addRequestInfo(request: NextRequest) {
  const requestHeaders = new Headers(request.headers);

  // Get IP address from various headers
  let ip =
    request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    request.headers.get('cf-connecting-ip') ||
    '0.0.0.0';

  // Convert localhost IPv6 to IPv4
  if (ip === '::1') {
    ip = '127.0.0.1';
  }

  // Get user agent
  const userAgent = request.headers.get('user-agent') || 'Unknown';

  // Set headers for later use
  requestHeaders.set('x-real-ip', ip);
  requestHeaders.set('user-agent', userAgent);

  return NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
}

// Then apply auth middleware
export default withAuth(
  // `withAuth` augments your `Request` with the user's token.
  async function middleware(request) {
    const response = await addRequestInfo(request);
    return response;
  },
  {
    pages: {
      signIn: '/auth/login',
    },
  }
);

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/settings/:path*',
    '/admin/:path*',
    '/api/auth/callback/credentials',
    '/api/auth/signin',
    '/api/auth/signout',
  ],
};
