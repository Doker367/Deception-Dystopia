import type { EChartsOption } from "echarts";

const AXIS = { color: "#71849b", fontSize: 10, fontFamily: "JetBrains Mono, monospace" };
const GRID = { color: "rgba(108, 150, 177, 0.12)", type: "dashed" as const };

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
