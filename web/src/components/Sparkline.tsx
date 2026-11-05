import { useId, useMemo } from "react";

interface SparklineProps {
  data: number[];
  color?: string;
  height?: number;
  width?: number;
  fill?: boolean;
}

export function Sparkline({
  data,
  color = "#35e6c4",
  height = 40,
  width = 132,
  fill = true,
}: SparklineProps) {
  const gradientId = useId();
  const series = data.length > 1 ? data : [0, 0];
  const { line, area } = useMemo(() => {
    const max = Math.max(...series, 1);
    const min = Math.min(...series, 0);
    const span = Math.max(max - min, 1);
    const step = width / Math.max(series.length - 1, 1);
    const points = series.map((value, index) => {
      const x = index * step;
      const y = height - 4 - ((value - min) / span) * (height - 8);
      return [x, y] as const;
    });
    const linePath = points.map(([x, y], index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
    return {
      line: linePath,
      area: `${linePath} L${width},${height} L0,${height} Z`,
    };
  }, [series, height, width]);

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="sparkline"
      role="img"
      aria-label="Tendencia de actividad"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.28" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={area} fill={`url(#${gradientId})`} />}
      <path d={line} fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <circle
        cx={width}
        cy={height - 4 - ((series[series.length - 1] - Math.min(...series, 0)) / Math.max(Math.max(...series, 1) - Math.min(...series, 0), 1)) * (height - 8)}
        r="2.4"
        fill={color}
      />
    </svg>
  );
}
