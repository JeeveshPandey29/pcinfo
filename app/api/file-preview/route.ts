import { NextRequest, NextResponse } from "next/server";
import { getFilePreview } from "../../../lib/file-scan";

export async function GET(request: NextRequest) {
  const targetPath = request.nextUrl.searchParams.get("path");

  if (!targetPath) {
    return NextResponse.json({ error: "Missing file path." }, { status: 400 });
  }

  try {
    const preview = await getFilePreview(targetPath);
    return NextResponse.json(preview);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to open safe preview.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
