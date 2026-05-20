import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useEffect, useState } from "react";
import { render, screen, fireEvent } from "@testing-library/react";

// PolicyEditor dynamically imports `@monaco-editor/react`, which pulls in
// the Monaco worker + DOM measurement code that jsdom cannot run. We stub
// the module with a textarea-shaped stand-in that still exercises the
// component's wiring: language prop, controlled value, and onChange relay.
vi.mock("@monaco-editor/react", () => {
  const Editor = ({
    value,
    onChange,
    language,
  }: {
    value: string;
    onChange: (next: string | undefined) => void;
    language?: string;
  }) => (
    <textarea
      data-testid="monaco-stub"
      data-language={language ?? ""}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  );
  return { __esModule: true, default: Editor };
});

// `next/dynamic` ships an SSR-aware loader that React can't resolve inside
// jsdom. Shim it with a state-driven async load so the dynamically-loaded
// stub component is rendered after a microtask flush.
vi.mock("next/dynamic", () => ({
  __esModule: true,
  default: (loader: () => Promise<{ default: unknown } | unknown>) => {
    return function DynamicShim(props: Record<string, unknown>) {
      const [Resolved, setResolved] = useState<
        React.ComponentType<Record<string, unknown>> | null
      >(null);
      useEffect(() => {
        let active = true;
        void Promise.resolve(loader()).then((mod) => {
          if (!active) return;
          const m = mod as { default?: unknown };
          const C = (m.default ?? mod) as React.ComponentType<
            Record<string, unknown>
          >;
          setResolved(() => C);
        });
        return () => {
          active = false;
        };
      }, []);
      if (!Resolved) return null;
      const C = Resolved;
      return <C {...props} />;
    };
  },
}));

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PolicyEditor (Monaco)", () => {
  it("renders the editor with the YAML language by default", async () => {
    const { PolicyEditor } = await import(
      "../components/policies/PolicyEditor"
    );
    render(<PolicyEditor value="version: '1'" onChange={() => {}} />);
    // The dynamic shim resolves on microtask; wait a tick.
    await Promise.resolve();
    await Promise.resolve();
    const node = await screen.findByTestId("monaco-stub");
    expect(node).toBeDefined();
    expect(node.getAttribute("data-language")).toBe("yaml");
    expect((node as HTMLTextAreaElement).value).toContain("version");
  });

  it("fires onChange when the underlying editor emits a change", async () => {
    const { PolicyEditor } = await import(
      "../components/policies/PolicyEditor"
    );
    const onChange = vi.fn();
    render(<PolicyEditor value="" onChange={onChange} />);
    await Promise.resolve();
    await Promise.resolve();
    const node = await screen.findByTestId("monaco-stub");
    fireEvent.change(node, { target: { value: "agent: test" } });
    expect(onChange).toHaveBeenCalledWith("agent: test");
  });
});
