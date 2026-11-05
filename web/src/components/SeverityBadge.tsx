import type { Severity } from "../types";

const LABEL: Record<Severity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Info",
};

export function SeverityBadge({ severity, dot = true }: { severity: Severity; dot?: boolean }) {
  return (
    <span className={`severity severity-${severity}`}>
      {dot && <i />}
      {LABEL[severity]}
    </span>
  );
}
