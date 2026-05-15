import { NextRequest } from "next/server";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";

const DASH_URL = process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002";

export async function POST(req: NextRequest) {
  const body = await req.json() as { format: "json" | "pdf"; agent_id?: string; from?: string; to?: string };
  const { format, agent_id, from, to } = body;

  const qs = new URLSearchParams();
  if (from) qs.set("from", from);
  if (to) qs.set("to", to);
  const path = agent_id ? `agents/${agent_id}/audit` : "activity";
  const query = qs.toString() ? `?${qs}` : "";

  let auditData: unknown[] = [];
  try {
    const res = await fetch(`${DASH_URL}/api/live/${path}${query}`);
    if (res.ok) auditData = await res.json() as unknown[];
  } catch {
    return Response.json({ ok: false, error: "Could not fetch audit data" }, { status: 503 });
  }

  if (format === "json") {
    return new Response(JSON.stringify(auditData, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="sauronid-audit-${Date.now()}.json"`,
      },
    });
  }

  if (format === "pdf") {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdf.embedFont(StandardFonts.HelveticaBold);

    page.drawText("SauronID — Audit Report", {
      x: 40, y: 780,
      size: 18, font: boldFont,
      color: rgb(0.1, 0.1, 0.1),
    });
    page.drawText(`Generated: ${new Date().toISOString()}`, {
      x: 40, y: 755,
      size: 10, font,
      color: rgb(0.5, 0.5, 0.5),
    });
    page.drawText(`Events: ${auditData.length}`, {
      x: 40, y: 735,
      size: 10, font,
      color: rgb(0.3, 0.3, 0.3),
    });

    let y = 700;
    for (const event of auditData.slice(0, 40)) {
      if (y < 60) break;
      const line = JSON.stringify(event).slice(0, 90);
      page.drawText(line, {
        x: 40, y,
        size: 7, font,
        color: rgb(0.3, 0.3, 0.3),
      });
      y -= 14;
    }

    const pdfBytes = await pdf.save();
    return new Response(pdfBytes.buffer as ArrayBuffer, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="sauronid-audit-${Date.now()}.pdf"`,
      },
    });
  }

  return Response.json({ ok: false, error: "Unsupported format" }, { status: 400 });
}
