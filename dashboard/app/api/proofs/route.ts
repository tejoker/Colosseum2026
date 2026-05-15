import { proxyLive } from "../_proxy";
export async function GET(req: Request) { return proxyLive("anchors", req); }
