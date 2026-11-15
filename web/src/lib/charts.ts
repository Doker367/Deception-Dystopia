import type { EChartsOption } from "echarts";
import { inkAccent, isLight, prefersReducedMotion } from "./theme";

// Tinta y rejilla cambian con el tema: gris claro sobre oscuro, gris profundo
// sobre blanco, para que ejes y etiquetas mantengan el contraste.
const axis = () => ({
  color: isLight() ? "#5d7186" : "#71849b",
  fontSize: 12,
  fontFamily: "JetBrains Mono, monospace",
});

export const chartAxis = axis;

const labelInk = () => (isLight() ? "#5d7186" : "#9fb1c3");

export const chartLabelInk = labelInk;

const grid = () => ({
  color: isLight() ? "rgba(90, 125, 150, 0.2)" : "rgba(108, 150, 177, 0.12)",
  type: "dashed" as const,
});

export const chartGrid = grid;

const tooltip = () =>
  isLight()
    ? {
        backgroundColor: "#ffffff",
        borderColor: "rgba(0, 0, 0, 0.24)",
        textStyle: { color: "#333333", fontSize: 13 },
        transitionDuration: 0.2,
      }
    : {
        backgroundColor: "#232322",
        borderColor: "rgba(255, 255, 255, 0.18)",
        textStyle: { color: "#f2f0ec", fontSize: 13 },
        transitionDuration: 0.2,
      };

export const chartTooltip = tooltip;

/**
 * Punto pulsante tipo radar para dar vida a una serie estática.
 * `showEffectOn: "render"` lo mantiene animándose aunque los datos no cambien;
 * con movimiento reducido solo se activa al pasar el cursor.
 */
export function ambientPulse(x: string | number, y: string | number, color: string) {
  return {
    type: "effectScatter" as const,
    id: "ambient-pulse",
    coordinateSystem: "cartesian2d" as const,
    symbolSize: 5,
    showEffectOn: prefersReducedMotion() ? ("emphasis" as const) : ("render" as const),
    rippleEffect: { period: 4, scale: 3.4, brushType: "stroke" as const },
    itemStyle: { color, shadowBlur: 8, shadowColor: color },
    z: 4,
    silent: true,
    tooltip: { show: false },
    data: [[x, y]],
    animation: !prefersReducedMotion(),
  };
}

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
  // Punto más reciente con actividad: mantiene un pulso aunque la serie no cambie.
  const last = [...buckets].reverse().find((bucket) => bucket.count > 0);
  const accent = inkAccent("#e2601f");
  return {
    backgroundColor: "transparent",
    animation: true,
    animationDuration: 700,
    animationDurationUpdate: 650,
    animationEasing: "cubicOut",
    animationEasingUpdate: "cubicOut",
    grid: { top: 18, right: 16, bottom: 38, left: 36 },
    tooltip: {
      trigger: "axis", ...tooltip(),
      formatter: (params: unknown) => {
        const point = (params as Array<{ dataIndex: number; value: number }>)[0];
        const bucket = point ? buckets[point.dataIndex] : undefined;
        return bucket ? `${tooltipLabel(Date.parse(bucket.at))} UTC<br/>${bucket.count} eventos` : "";
      },
    },
    // Eje de categorías: las etiquetas corresponden exactamente a los buckets y
    // no se duplican ni se extienden a días vacíos como ocurre con el eje time.
    xAxis: { type: "category", data: buckets.map(({ at }) => label(Date.parse(at))),
      axisLabel: { ...axis(), hideOverlap: true },
      axisLine: { lineStyle: grid() }, axisTick: { show: false }, splitLine: { show: false } },
    yAxis: { type: "value", minInterval: 1, axisLabel: axis(), splitLine: { lineStyle: grid() } },
    series: [{ type: "bar", id: "timeline", barMaxWidth: 15, barMinWidth: 3,
      universalTransition: true,
      emphasis: { focus: "series" },
      blur: { itemStyle: { opacity: 0.4 } },
      animationDelay: (index: number) => index * 14,
      itemStyle: { color: accent, borderRadius: [3, 3, 0, 0] },
      data: buckets.map(({ count }) => count) },
      ...(last ? [ambientPulse(label(Date.parse(last.at)), last.count, accent)] : []),
    ],
  };
}

export function horizontalBarOption(
  labels: string[],
  values: number[],
  colors: string[],
  suffix = "",
): EChartsOption {
  const maxIndex = values.reduce((best, value, index) => (value > (values[best] ?? -Infinity) ? index : best), 0);
  const pulse = (values[maxIndex] ?? 0) > 0
    ? [ambientPulse(values[maxIndex], labels[maxIndex], inkAccent(colors[maxIndex % colors.length]))]
    : [];
  return {
    backgroundColor: "transparent",
    animation: true,
    animationDuration: 1000,
    animationDurationUpdate: 700,
    animationEasing: "cubicOut",
    animationEasingUpdate: "cubicOut",
    grid: { top: 8, right: 42, bottom: 18, left: 82 },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      ...tooltip(),
      formatter: (params: unknown) => {
        const item = (params as Array<{ name: string; value: number }>)[0];
        return item ? `<b>${item.name}</b><br/>${new Intl.NumberFormat("es-MX").format(item.value)}${suffix}` : "";
      },
    },
    xAxis: {
      type: "value",
      splitLine: { lineStyle: grid() },
      axisLabel: { ...axis(), formatter: (value: number) => (value >= 1000 ? `${(value / 1000).toFixed(1)}k` : `${value}`) },
    },
    yAxis: {
      type: "category",
      data: labels,
      axisTick: { show: false },
      axisLine: { show: false },
      axisLabel: { ...axis(), color: labelInk(), fontSize: 11 },
    },
    series: [
      {
        type: "bar",
        id: "ranking",
        universalTransition: true,
        emphasis: { focus: "series" },
        blur: { itemStyle: { opacity: 0.45 } },
        animationDelay: (index: number) => index * 40,
        data: values.map((value, index) => ({
          value,
          itemStyle: {
            borderRadius: [0, 3, 3, 0],
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 1,
              y2: 0,
              colorStops: [
                { offset: 0, color: `${inkAccent(colors[index % colors.length])}55` },
                { offset: 1, color: inkAccent(colors[index % colors.length]) },
              ],
            },
          },
        })),
        barWidth: 11,
        showBackground: true,
        backgroundStyle: { color: "rgba(255, 255, 255, 0.06)", borderRadius: 3 },
        label: {
          show: true,
          position: "right",
          color: labelInk(),
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 11,
          formatter: (params: unknown) => {
            const value = Number((params as { value: number }).value);
            return value >= 1000 ? `${(value / 1000).toFixed(1)}k` : `${value}`;
          },
        },
      },
      ...pulse,
    ],
  };
}

export function verticalBarOption(
  labels: string[],
  values: number[],
  colors: string[],
  suffix = "",
): EChartsOption {
  const maxIndex = values.reduce((best, value, index) => (value > (values[best] ?? -Infinity) ? index : best), 0);
  const pulse = (values[maxIndex] ?? 0) > 0
    ? [ambientPulse(labels[maxIndex], values[maxIndex], inkAccent(colors[maxIndex % colors.length]))]
    : [];
  return {
    backgroundColor: "transparent",
    animation: true,
    animationDuration: 1000,
    animationDurationUpdate: 700,
    animationEasing: "cubicOut",
    animationEasingUpdate: "cubicOut",
    grid: { top: 20, right: 12, bottom: 42, left: 36 },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      ...tooltip(),
      formatter: (params: unknown) => {
        const item = (params as Array<{ name: string; value: number }>)[0];
        return item ? `<b>${item.name}</b><br/>${new Intl.NumberFormat("es-MX").format(item.value)}${suffix}` : "";
      },
    },
    xAxis: {
      type: "category",
      data: labels,
      axisTick: { show: false },
      axisLine: { lineStyle: { color: grid().color } },
      axisLabel: { ...axis(), interval: 0, rotate: labels.length > 6 ? 24 : 0 },
    },
    yAxis: {
      type: "value",
      splitLine: { lineStyle: grid() },
      axisLabel: { ...axis(), formatter: (value: number) => (value >= 1000 ? `${(value / 1000).toFixed(1)}k` : `${value}`) },
    },
    series: [
      {
        type: "bar",
        id: "distribution",
        universalTransition: true,
        emphasis: { focus: "series" },
        blur: { itemStyle: { opacity: 0.45 } },
        animationDelay: (index: number) => index * 45,
        data: values.map((value, index) => ({
          value,
          itemStyle: {
            borderRadius: [3, 3, 0, 0],
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: inkAccent(colors[index % colors.length]) },
                { offset: 1, color: `${inkAccent(colors[index % colors.length])}33` },
              ],
            },
          },
        })),
        barWidth: "42%",
        showBackground: true,
        backgroundStyle: { color: "rgba(255, 255, 255, 0.05)", borderRadius: [3, 3, 0, 0] },
      },
      ...pulse,
    ],
  };
}
