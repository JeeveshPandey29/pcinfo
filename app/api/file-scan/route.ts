import { NextResponse } from "next/server";
import { getFileScan } from "../../../lib/file-scan";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const result = await getFileScan();
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      {
        error: "Unable to scan files.",
        detail: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
}
