import { NextResponse } from "next/server";

export async function POST() {
  return NextResponse.json(
    { valid: false, error: "Device auth is not enabled in the active core contract" },
    { status: 410 }
  );
}
