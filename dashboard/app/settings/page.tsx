import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { fetchCompanies, fetchPeople } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { fmtNumber, fmtTimestamp } from "@/lib/format";

export default async function SettingsPage() {
  const t = await getTranslations("settings");
  const [companiesResult, peopleResult] = await Promise.all([
    fetchCompanies(),
    fetchPeople(),
  ]);

  const companies = companiesResult.ok ? companiesResult.data : [];
  const people = peopleResult.ok ? peopleResult.data : [];

  return (
    <PageShell title={t("title")}>
      {/* Companies */}
      <section className="mb-10">
        <h2 className="text-mono-sm text-[var(--text-muted)] uppercase mb-4">
          {t("tabCompanies")}
        </h2>
        {companies.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)] py-8">{t("companiesEmpty")}</p>
        ) : (
          <Table>
            <Thead>
              <tr>
                <Th>{t("colName")}</Th>
                <Th>{t("colAgents")}</Th>
                <Th>{t("colRegistered")}</Th>
              </tr>
            </Thead>
            <Tbody>
              {companies.map((c) => (
                <Tr key={c.id}>
                  <Td>
                    <Link
                      href={`/companies/${c.id}`}
                      className="text-[var(--text-primary)] hover:text-[var(--accent)] transition-colors duration-150 ease-out"
                    >
                      {c.name}
                    </Link>
                  </Td>
                  <Td>{fmtNumber(c.agent_count)}</Td>
                  <Td>
                    <span className="text-mono-sm text-[var(--text-muted)]">
                      {fmtTimestamp(c.created_at)}
                    </span>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </section>

      {/* People */}
      <section className="mb-10">
        <h2 className="text-mono-sm text-[var(--text-muted)] uppercase mb-4">
          {t("tabPeople")}
        </h2>
        {people.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)] py-8">{t("peopleEmpty")}</p>
        ) : (
          <Table>
            <Thead>
              <tr>
                <Th>{t("colName")}</Th>
                <Th>{t("tabCompanies")}</Th>
                <Th>{t("colRegistered")}</Th>
              </tr>
            </Thead>
            <Tbody>
              {people.map((p) => (
                <Tr key={p.id}>
                  <Td className="text-[var(--text-primary)]">{p.name}</Td>
                  <Td>{p.company_name}</Td>
                  <Td>
                    <span className="text-mono-sm text-[var(--text-muted)]">
                      {fmtTimestamp(p.created_at)}
                    </span>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </section>

      {/* Configuration */}
      <section>
        <h2 className="text-mono-sm text-[var(--text-muted)] uppercase mb-4">
          {t("tabConfig")}
        </h2>
        <dl className="space-y-3 max-w-md">
          {[
            [t("configCoreUrl"),  process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001"],
            [t("configDashUrl"),  process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002"],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between text-sm py-2 border-b border-[var(--border)]">
              <dt className="text-[var(--text-muted)]">{label}</dt>
              <dd className="text-mono-sm text-[var(--text-secondary)]">{value}</dd>
            </div>
          ))}
        </dl>
      </section>
    </PageShell>
  );
}
