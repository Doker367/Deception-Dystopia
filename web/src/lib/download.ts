export function downloadBlob(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function downloadJson(filename: string, data: unknown) {
  downloadBlob(filename, JSON.stringify(data, null, 2), "application/json;charset=utf-8");
}

export function downloadCsv(filename: string, rows: Array<Array<string | number | boolean | null | undefined>>) {
  const csv = rows
    .map((row) => row.map((value) => `"${String(value ?? "").replace(/"/g, '""')}"`).join(","))
    .join("\n");
  downloadBlob(filename, csv, "text/csv;charset=utf-8");
}
