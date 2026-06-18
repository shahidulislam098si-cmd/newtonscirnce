import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

const protectedRoutes = ['/dashboard', '/create-bill', '/bills', '/settings'];
const publicRoutes = ['/login'];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const isProtected = protectedRoutes.some((route) => pathname.startsWith(route));
  const isPublic = publicRoutes.some((route) => pathname.startsWith(route));

  const token = request.cookies.get('token')?.value;
  const jwtSecret = process.env.JWT_SECRET;

  // Treat missing JWT_SECRET the same as an invalid token — never crash the middleware
  const verifyJwt = async (t: string): Promise<boolean> => {
    if (!jwtSecret) return false;
    try {
      const secret = new TextEncoder().encode(jwtSecret);
      await jwtVerify(t, secret);
      return true;
    } catch {
      return false;
    }
  };

  if (isProtected) {
    if (!token) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    const valid = await verifyJwt(token);
    if (valid) return NextResponse.next();
    const response = NextResponse.redirect(new URL('/login', request.url));
    response.cookies.delete('token');
    return response;
  }

  if (isPublic && token) {
    const valid = await verifyJwt(token);
    if (valid) return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf|eot|css|js)).*)',
  ],
};
