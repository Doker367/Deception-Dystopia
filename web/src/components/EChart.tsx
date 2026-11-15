import { useEffect, useRef } from "react";
import * as echarts from "echarts";
import type { ECElementEvent, EChartsOption } from "echarts";

interface EChartProps {
  option: EChartsOption;
  className?: string;
  height?: number;
  /** Callback opcional para clics en elementos de una serie (p. ej. nodos). */
  onElementClick?: (params: ECElementEvent) => void;
}

export function EChart({ option, className = "", height = 260, onElementClick }: EChartProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);
  const clickRef = useRef(onElementClick);

  useEffect(() => {
    clickRef.current = onElementClick;
  }, [onElementClick]);

  // La instancia vive todo el ciclo del componente: así ECharts puede animar
  // transiciones de actualización en vez de reconstruir el lienzo.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const chart = echarts.init(container, undefined, { renderer: "canvas" });
    chartRef.current = chart;
    const onClick = (params: ECElementEvent) => clickRef.current?.(params);
    chart.on("click", onClick);
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(container);
    return () => {
      observer.disconnect();
      chart.off("click", onClick);
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    chartRef.current?.setOption(option, { notMerge: false, lazyUpdate: true });
  }, [option]);

  return <div ref={containerRef} className={`echart ${className}`.trim()} style={{ height }} />;
}
