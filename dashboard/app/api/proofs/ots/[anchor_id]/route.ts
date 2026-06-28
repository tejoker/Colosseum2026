// Download the OpenTimestamps `.ots` proof for one Bitcoin merkle anchor.
//
//   GET /api/proofs/ots/:anchor_id → proxies core GET /admin/anchor/ots/:id
//
// The core reconstructs a standards-compliant detached `.ots` from the stored
// calendar receipt; this route streams those raw bytes to the browser as a
// download. A reviewer can then run `ots upgrade` + `ots info`/`ots verify` to
// confirm the Merkle root is committed to Bitcoin — no trust in us required.

import { proxyCoreBinary } from "../../../_proxy";

export const dynamic = "force-dynamic";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ anchor_id: string }> }
) {
  const { anchor_id } = await params;
  const id = encodeURIComponent(anchor_id);
  const safe = anchor_id.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 24) || "anchor";
  return proxyCoreBinary(`anchor/ots/${id}`, req, `sauronid-${safe}.ots`);
}
