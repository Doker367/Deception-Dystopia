import type { ReactNode } from "react";
import { ArrowDownRight, ArrowUpRight } from "lucide-react";
import { Sparkline } from "./Sparkline";
import { AnimatedNumber } from "./AnimatedNumber";
import { ACCENTS } from "../lib/palette";

interface MetricCardProps {
  label: string;
  value: string;
  detail: string;
  delta?: string;
  trend?: "up" | "down" | "flat";
  icon: ReactNode;
  tone?: "cyan" | "blue" | "amber" | "violet" | "red";
  spark?: number[];
}

const TONE_COLOR: Record<string, string> = {
  cyan: ACCENTS.cyan,
  blue: ACCENTS.blue,
  amber: ACCENTS.amber,
  violet: ACCENTS.violet,
  red: ACCENTS.red,
};

export function MetricCard({
  label,
  value,
  detail,
  delta,
  trend = "up",
  icon,
  tone = "cyan",
  spark,
}: MetricCardProps) {
  return (
    <article className={`metric-card tone-${tone}`}>
      <div className="metric-top">
        <span className="metric-icon">{icon}</span>
        <span className="metric-label">{label}</span>
        {delta && (
          <span className={`metric-delta ${trend}`}>
            {trend === "up" ? <ArrowUpRight size={13} /> : trend === "down" ? <ArrowDownRight size={13} /> : null}
            {delta}
          </span>
        )}
      </div>
      <div className="metric-main">
        <div>
          <strong className="metric-value"><AnimatedNumber value={value} /></strong>
          <p className="metric-detail">{detail}</p>
        </div>
        {spark && (
          <div className="metric-spark">
            <Sparkline
              data={spark}
              color={TONE_COLOR[tone] ?? ACCENTS.cyan}
              width={108}
              height={38}
            />
          </div>
        )}
      </div>
    </article>
  );
}
