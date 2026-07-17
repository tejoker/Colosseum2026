import { fetchCoreJson } from "../../_proxy";

// Per-batch anchor proofs: each row is a Merkle root committed to Bitcoin.
interface CoreBatch {
  anchor_id: string;
  batch_root_hex: string;
  n_actions: number;
  created_at: number;
  bitcoin?: { ots_upgraded?: boolean };
  btc_anchor_id?: string;
}

export async function GET(req: Request) {
  const r = await fetchCoreJson<CoreBatch[]>("anchor/batches", "", req);
  if (!r.ok) return r.response;
  const out = (r.data || []).slice(0, 25).map((b) => ({
    anchor_id: b.anchor_id,
    root: b.batch_root_hex,
    n_actions: b.n_actions,
    created_at: new Date((b.created_at || 0) * 1000).toISOString(),
    btc_confirmed: !!b.bitcoin?.ots_upgraded,
    btc_anchor_id: b.btc_anchor_id || "",
  }));
  return Response.json(out);
}
