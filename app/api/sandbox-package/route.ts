import { NextRequest, NextResponse } from "next/server";
import { createSandboxPackage } from "../../../lib/file-scan";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as { path?: string };
    const sourcePath = body.path?.trim();

    if (!sourcePath) {
      return NextResponse.json({ error: "File path is required." }, { status: 400 });
    }

    const result = await createSandboxPackage(sourcePath);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      {
        error: "Unable to prepare sandbox package.",
        detail: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
}
