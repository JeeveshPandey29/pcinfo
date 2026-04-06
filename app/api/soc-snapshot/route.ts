import { NextResponse } from "next/server";
import { getDeviceSnapshot } from "../../../lib/soc";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const snapshot = await getDeviceSnapshot();
    return NextResponse.json(snapshot);
  } catch (error) {
    return NextResponse.json(
      {
        error: "Unable to collect device snapshot.",
        detail: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
}


