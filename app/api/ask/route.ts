import { NextRequest, NextResponse } from "next/server";
import { getDeviceSnapshot } from "../../../lib/soc";
import type { AskResponse } from "../../../lib/types";

export const dynamic = "force-dynamic";

function buildLocalAnswer(question: string, snapshot: Awaited<ReturnType<typeof getDeviceSnapshot>>): string {
  const cards = snapshot.cards
    .map((card) => `${card.title}: ${card.summary}`)
    .join(" ");

  if (/timeline/i.test(question)) {
    return `This timeline is built from your local Windows signals, not demo data. It currently includes firewall state, failed sign-in counts, and recent PowerShell-related events seen on ${snapshot.deviceName}. ${snapshot.timeline
      .map((item) => `${item.title} at ${item.time}`)
      .join(". ")}.`;
  }

  if (/safe|risk|danger|secure/i.test(question)) {
    return `${snapshot.deviceName} is currently rated ${snapshot.overviewStory.status}. ${snapshot.overviewStory.explanation}`;
  }

  return `${snapshot.overviewStory.headline} ${snapshot.overviewStory.explanation} ${cards}`;
}

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as { question?: string };
    const question = body.question?.trim();

    if (!question) {
      return NextResponse.json({ error: "Question is required." }, { status: 400 });
    }

    const snapshot = await getDeviceSnapshot();
    const apiKey = process.env.OPENAI_API_KEY;

    if (!apiKey) {
      const local: AskResponse = {
        answer: buildLocalAnswer(question, snapshot),
        source: "local",
      };

      return NextResponse.json(local);
    }

    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4.1",
        input: [
          {
            role: "system",
            content: [
              {
                type: "input_text",
                text:
                  "You are SafePulse, a device security assistant. Explain only from the provided laptop snapshot. Keep answers concise, plain-English, and do not invent signals that are not in the snapshot. When confidence is limited, say so clearly.",
              },
            ],
          },
          {
            role: "user",
            content: [
              {
                type: "input_text",
                text: `Laptop snapshot: ${JSON.stringify(snapshot)}\n\nQuestion: ${question}`,
              },
            ],
          },
        ],
      }),
    });

    if (!response.ok) {
      const local: AskResponse = {
        answer: buildLocalAnswer(question, snapshot),
        source: "local",
      };

      return NextResponse.json(local);
    }

    const json = (await response.json()) as {
      output_text?: string;
      output?: Array<{ content?: Array<{ text?: string }> }>;
    };

    const answer =
      json.output_text ||
      json.output?.flatMap((item) => item.content || []).map((item) => item.text || "").join(" ").trim() ||
      buildLocalAnswer(question, snapshot);

    const result: AskResponse = {
      answer,
      source: "openai",
    };

    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      {
        error: "Unable to answer question.",
        detail: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
}


