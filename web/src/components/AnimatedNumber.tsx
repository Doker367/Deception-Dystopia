import NumberFlow from "@number-flow/react";

interface AnimatedNumberProps {
  /** Valor ya formateado ("12,847", "1.2 s", "4.2 GB") o número puro. */
  value: string | number;
  className?: string;
}

/**
 * Anima el tramo numérico de un valor formateado y conserva el sufijo literal
 * ("s", "GB", "eventos"…). El formato y el respeto a `prefers-reduced-motion`
 * los gestiona NumberFlow (MIT, barvian/number-flow).
 */
export function AnimatedNumber({ value, className }: AnimatedNumberProps) {
  const text = typeof value === "number" ? String(value) : value;
  const match = /^(-?[\d.,]+)(.*)$/.exec(text.trim());
  if (!match) return <span className={className}>{text}</span>;

  const numericText = match[1].trim();
  const suffix = match[2];
  // Separa miles (1.204 / 1,204) de decimales (1.2) sin depender del locale.
  const normalized = numericText
    .replace(/[.,](?=\d{3}(?:\D|$))/g, "")
    .replace(",", ".");
  const numeric = Number(normalized);
  if (!Number.isFinite(numeric)) return <span className={className}>{text}</span>;

  const decimals = (normalized.split(".")[1] ?? "").length;

  return (
    <span className={className}>
      <NumberFlow
        value={numeric}
        locales="es-MX"
        format={{ minimumFractionDigits: decimals, maximumFractionDigits: decimals }}
        respectMotionPreference
      />
      {suffix ? <span style={{ whiteSpace: "pre" }}>{suffix}</span> : null}
    </span>
  );
}
