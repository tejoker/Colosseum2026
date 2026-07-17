import { cookies } from "next/headers";
import { SESSION_COOKIE } from "@/lib/session";

export async function POST(): Promise<Response> {
  const jar = await cookies();
  jar.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0,
  });
  return Response.json({ ok: true });
}
