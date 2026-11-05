import type { ReactNode } from "react";
import { ArrowDownRight, ArrowUpRight } from "lucide-react";
import { Sparkline } from "./Sparkline";

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
          <strong className="metric-value">{value}</strong>
          <p className="metric-detail">{detail}</p>
        </div>
        {spark && (
          <div className="metric-spark">
            <Sparkline
              data={spark}
              color={tone === "red" ? "#ff6b7a" : tone === "amber" ? "#f5b75b" : tone === "blue" ? "#5aa9ff" : tone === "violet" ? "#b58cff" : "#35e6c4"}
              width={108}
              height={38}
            />
          </div>
        )}
      </div>
    </article>
  );
}
