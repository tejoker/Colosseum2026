import { fetchCoreJson } from "../../_proxy";

// Per-batch anchor proofs. Whether a row is committed to Bitcoin at all depends
// on the provider that wrote it: rows written by the mock provider have a
// synthetic txid, no downloadable .ots, and belong on no chain. The provider is
// per row because a deployment can be switched from mock to opentimestamps and
// keep its history.
interface CoreBatch {
  anchor_id: string;
  batch_root_hex: string;
  n_actions: number;
  created_at: number;
  bitcoin?: { ots_upgraded?: boolean; provider?: string };
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
    btc_provider: b.bitcoin?.provider || "",
  }));
  return Response.json(out);
}
