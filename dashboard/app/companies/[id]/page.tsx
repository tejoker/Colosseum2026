import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { fetchCompany, fetchCompanyPeople } from "@/lib/api";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { fmtNumber, fmtTimestamp } from "@/lib/format";

interface Props {
  params: Promise<{ id: string }>;
}

export const dynamic = "force-dynamic";

export default async function CompanyPage({ params }: Props) {
  const { id } = await params;
  const t = await getTranslations("company");
  const ts = await getTranslations("settings");
  const tc = await getTranslations("common");

  const [companyResult, peopleResult] = await Promise.all([
    fetchCompany(id),
    fetchCompanyPeople(id),
  ]);

  const company = companyResult.ok ? companyResult.data : null;
  const people = peopleResult.ok ? peopleResult.data : [];

  return (
    <main id="main" className="pt-20 pb-16 px-6 max-w-3xl mx-auto">
      {/* Breadcrumb */}
      <Link
        href="/settings"
        className="text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors duration-150 ease-out mb-6 inline-block"
      >
        ← {t("back")}
      </Link>

      {/* Heading */}
      <h1 className="text-2xl font-semibold text-[var(--text-primary)] mb-1">
        {company?.name ?? id}
      </h1>

      {/* Stat line */}
      {company && (
        <p className="text-sm text-[var(--text-muted)] mb-10">
          {t("statPeople", { count: people.length })}
          {" · "}
          {t("statAgents", { count: company.agent_count })}
          {" · "}
          {ts("colRegistered").toLowerCase()} {fmtTimestamp(company.created_at)}
        </p>
      )}

      {/* People */}
      <section>
        <h2 className="text-mono-sm text-[var(--text-muted)] uppercase mb-4">
          {t("people")}
        </h2>
        {people.length === 0 ? (
          <div className="py-8">
            <p className="text-sm text-[var(--text-muted)] mb-2">{t("empty")}</p>
            <Link
              href="/welcome"
              className="text-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)] transition-colors duration-150"
            >
              {tc("emptyCta")} →
            </Link>
          </div>
        ) : (
          <Table>
            <Thead>
              <tr>
                <Th>{t("colName")}</Th>
                <Th>{t("colEmail")}</Th>
                <Th>{t("colRegistered")}</Th>
              </tr>
            </Thead>
            <Tbody>
              {people.map((p) => (
                <Tr key={p.id}>
                  <Td className="text-[var(--text-primary)]">{p.name}</Td>
                  <Td>
                    <span className="text-mono text-[var(--text-secondary)]">{p.email}</span>
                  </Td>
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
    </main>
  );
}
