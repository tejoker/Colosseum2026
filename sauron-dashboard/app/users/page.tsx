"use client";

import { useDash } from "../context/DashContext";
import { Card, Kpi, PageHeader, Spinner, fmtNum } from "../shared";

export default function UsersPage() {
  const { users, loading } = useDash();

  if (loading) return <Spinner />;

  return (
    <div className="space-y-12">
      <PageHeader
        eyebrow="HUMAN.REGISTRY"
        hex="0x500"
        title={
          <>
            The{" "}
            <em className="not-italic gradient-text font-display">key images</em>{" "}
            behind every agent.
          </>
        }
        description="Each human is a stable OPRF key-image. Agents are bound to one. Revoke the human, every agent it owns dies."
      />

      <div className="grid grid-cols-2 md:grid-cols-3 gap-5">
        <Kpi label="HUMANS" value={fmtNum(users.length)} accent="cyan" />
        <Kpi
          label="JURISDICTIONS"
          value={fmtNum(new Set(users.map((u) => u.nationality)).size)}
          sub="DISTINCT NATIONALITIES"
        />
        <Kpi
          label="WITH NATIONALITY"
          value={fmtNum(users.filter((u) => u.nationality).length)}
          sub="OPRF-VERIFIED"
        />
      </div>

      <Card title={`USER.LIST · ${users.length}`} hex="0x510">
        <div className="overflow-x-auto -mx-3">
          {users.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <span className="font-mono-label text-[9.5px] text-white/35">EMPTY</span>
              <p className="text-[12px] text-white/45">No users registered yet.</p>
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left">
                  <Th>FIRST NAME</Th>
                  <Th>LAST NAME</Th>
                  <Th>NATIONALITY</Th>
                  <Th>KEY.IMAGE</Th>
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => (
                  <tr key={u.key_image_hex ?? i} className="border-t border-white/[0.04]">
                    <Td>{u.first_name}</Td>
                    <Td>{u.last_name}</Td>
                    <Td muted>{u.nationality}</Td>
                    <Td mono dim>{u.key_image_hex?.slice(0, 18)}…</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="font-mono-label text-[8.5px] text-white/40 px-3 py-4 font-normal">
      {children}
    </th>
  );
}

function Td({
  children,
  mono,
  dim,
  muted,
}: {
  children: React.ReactNode;
  mono?: boolean;
  dim?: boolean;
  muted?: boolean;
}) {
  let cls = "text-white/85";
  if (mono) cls = "font-mono text-[11px] text-white/85";
  if (mono && dim) cls = "font-mono text-[11px] text-white/40";
  if (muted) cls = "text-white/55";
  return (
    <td className={`px-3 py-4 align-middle whitespace-nowrap ${cls}`}>
      {children}
    </td>
  );
}
