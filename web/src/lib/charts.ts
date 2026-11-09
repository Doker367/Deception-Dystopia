import type { EChartsOption } from "echarts";

const AXIS = { color: "#71849b", fontSize: 10, fontFamily: "JetBrains Mono, monospace" };
const GRID = { color: "rgba(108, 150, 177, 0.12)", type: "dashed" as const };

export function attackerTimelineOption(
  buckets: Array<{ at: string; count: number }>,
  interval: "1h" | "1d",
): EChartsOption {
  // Etiquetas cortas: la hora sola en 1h y el día en 1d. El tooltip conserva
  // la fecha completa para no perder contexto.
  const label = (stamp: number) => new Intl.DateTimeFormat("es-MX", {
    timeZone: "UTC",
    ...(interval === "1h"
      ? { hour: "2-digit", minute: "2-digit", hourCycle: "h23" as const }
      : { day: "2-digit", month: "2-digit" }),
  }).format(stamp);
  const tooltipLabel = (stamp: number) => new Intl.DateTimeFormat("es-MX", {
    timeZone: "UTC", day: "2-digit", month: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).format(stamp);
  return {
    backgroundColor: "transparent",
    animationDuration: 300,
    grid: { top: 18, right: 16, bottom: 38, left: 36 },
    tooltip: {
      trigger: "axis", backgroundColor: "#0b1520", borderColor: "rgba(93, 170, 196, 0.3)",
      textStyle: { color: "#dbe7f3", fontSize: 11 },
      formatter: (params: unknown) => {
        const point = (params as Array<{ dataIndex: number; value: number }>)[0];
        const bucket = point ? buckets[point.dataIndex] : undefined;
        return bucket ? `${tooltipLabel(Date.parse(bucket.at))} UTC<br/>${bucket.count} eventos` : "";
      },
    },
    // Eje de categorías: las etiquetas corresponden exactamente a los buckets y
    // no se duplican ni se extienden a días vacíos como ocurre con el eje time.
    xAxis: { type: "category", data: buckets.map(({ at }) => label(Date.parse(at))),
      axisLabel: { ...AXIS, hideOverlap: true },
      axisLine: { lineStyle: GRID }, axisTick: { show: false }, splitLine: { show: false } },
    yAxis: { type: "value", minInterval: 1, axisLabel: AXIS, splitLine: { lineStyle: GRID } },
    series: [{ type: "bar", barMaxWidth: 15, barMinWidth: 3,
      itemStyle: { color: "#42c6d5", borderRadius: [3, 3, 0, 0] },
      data: buckets.map(({ count }) => count) }],
  };
}

export function horizontalBarOption(
  labels: string[],
  values: number[],
  colors: string[],
  suffix = "",
): EChartsOption {
  return {
    backgroundColor: "transparent",
    animationDuration: 900,
    grid: { top: 8, right: 42, bottom: 18, left: 82 },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      backgroundColor: "#0b1520",
      borderColor: "rgba(93, 170, 196, 0.3)",
      textStyle: { color: "#dbe7f3", fontSize: 11 },
      formatter: (params: unknown) => {
        const item = (params as Array<{ name: string; value: number }>)[0];
        return item ? `<b>${item.name}</b><br/>${new Intl.NumberFormat("es-MX").format(item.value)}${suffix}` : "";
      },
    },
    xAxis: {
      type: "value",
      splitLine: { lineStyle: GRID },
      axisLabel: { ...AXIS, formatter: (value: number) => (value >= 1000 ? `${(value / 1000).toFixed(1)}k` : `${value}`) },
    },
    yAxis: {
      type: "category",
      data: labels,
      axisTick: { show: false },
      axisLine: { show: false },
      axisLabel: { ...AXIS, color: "#9fb1c3", fontSize: 9 },
    },
    series: [
      {
        type: "bar",
        data: values.map((value, index) => ({
          value,
          itemStyle: {
            borderRadius: [0, 5, 5, 0],
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 1,
              y2: 0,
              colorStops: [
                { offset: 0, color: `${colors[index % colors.length]}55` },
                { offset: 1, color: colors[index % colors.length] },
              ],
            },
          },
        })),
        barWidth: 11,
        showBackground: true,
        backgroundStyle: { color: "rgba(88, 117, 139, 0.09)", borderRadius: 5 },
        label: {
          show: true,
          position: "right",
          color: "#9fb1c3",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 8,
          formatter: (params: unknown) => {
            const value = Number((params as { value: number }).value);
            return value >= 1000 ? `${(value / 1000).toFixed(1)}k` : `${value}`;
          },
        },
      },
    ],
  };
}

export function verticalBarOption(
  labels: string[],
  values: number[],
  colors: string[],
  suffix = "",
): EChartsOption {
  return {
    backgroundColor: "transparent",
    animationDuration: 900,
    grid: { top: 20, right: 12, bottom: 42, left: 36 },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      backgroundColor: "#0b1520",
      borderColor: "rgba(93, 170, 196, 0.3)",
      textStyle: { color: "#dbe7f3", fontSize: 11 },
      formatter: (params: unknown) => {
        const item = (params as Array<{ name: string; value: number }>)[0];
        return item ? `<b>${item.name}</b><br/>${new Intl.NumberFormat("es-MX").format(item.value)}${suffix}` : "";
      },
    },
    xAxis: {
      type: "category",
      data: labels,
      axisTick: { show: false },
      axisLine: { lineStyle: { color: "rgba(108, 150, 177, 0.16)" } },
      axisLabel: { ...AXIS, interval: 0, rotate: labels.length > 6 ? 24 : 0 },
    },
    yAxis: {
      type: "value",
      splitLine: { lineStyle: GRID },
      axisLabel: { ...AXIS, formatter: (value: number) => (value >= 1000 ? `${(value / 1000).toFixed(1)}k` : `${value}`) },
    },
    series: [
      {
        type: "bar",
        data: values.map((value, index) => ({
          value,
          itemStyle: {
            borderRadius: [5, 5, 0, 0],
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: colors[index % colors.length] },
                { offset: 1, color: `${colors[index % colors.length]}33` },
              ],
            },
          },
        })),
        barWidth: "42%",
        showBackground: true,
        backgroundStyle: { color: "rgba(88, 117, 139, 0.08)", borderRadius: [5, 5, 0, 0] },
      },
    ],
  };
}
