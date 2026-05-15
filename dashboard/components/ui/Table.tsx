import { ReactNode } from "react";

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  );
}

export function Thead({ children }: { children: ReactNode }) {
  return <thead>{children}</thead>;
}

export function Tbody({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>;
}

export function Th({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <th
      className={`text-left text-mono-sm text-[var(--text-muted)] uppercase py-2.5 px-4 border-b border-[var(--border)] font-normal ${className}`}
    >
      {children}
    </th>
  );
}

export function Td({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <td
      className={`py-3 px-4 border-b border-[var(--border)] text-[var(--text-secondary)] ${className}`}
    >
      {children}
    </td>
  );
}

export function Tr({
  children,
  onClick,
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <tr
      className={`transition-colors duration-150 ease-out ${
        onClick ? "cursor-pointer hover:bg-[var(--bg-elevated)]" : ""
      } ${className}`}
      onClick={onClick}
    >
      {children}
    </tr>
  );
}
