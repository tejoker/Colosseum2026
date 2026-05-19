import { NextRequest } from "next/server";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import { fetchCoreJson } from "../_proxy";
import {
  adaptActivity,
  adaptAuditEvents,
  buildAgentNameMap,
  filterReceiptsByAgent,
  type CoreActionReceipt,
  type CoreAgentRecord,
} from "../_adapters";

export async function POST(req: NextRequest) {
  const body = (await req.json()) as {
    format: "json" | "pdf";
    agent_id?: string;
    from?: string;
    to?: string;
  };
  const { format, agent_id, from, to } = body;

  // Pull receipts + agents directly from the core (same path the /api/activity
  // and /api/agents/[id]/audit handlers use) so export is consistent with what
  // the user sees in the UI.
  const [receiptsR, agentsR] = await Promise.all([
    fetchCoreJson<CoreActionReceipt[]>("agent_actions/recent", "?limit=1000"),
    fetchCoreJson<CoreAgentRecord[]>("agents"),
  ]);
  if (!receiptsR.ok) return receiptsR.response;
  const agents = agentsR.ok ? agentsR.data : [];

  let rows = receiptsR.data;
  if (agent_id) rows = filterReceiptsByAgent(rows, agent_id);
  if (from) {
    const fromSec = Math.floor(new Date(from).getTime() / 1000);
    rows = rows.filter((x) => x.created_at >= fromSec);
  }
  if (to) {
    const toSec = Math.floor(new Date(to).getTime() / 1000);
    rows = rows.filter((x) => x.created_at <= toSec);
  }

  const auditData: unknown[] = agent_id
    ? adaptAuditEvents(rows)
    : adaptActivity(rows, buildAgentNameMap(agents));

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
