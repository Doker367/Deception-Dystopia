import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, X } from "lucide-react";
import { apiGet, apiPut } from "../lib/api";
import { Portal } from "./Portal";

interface SaveResult {
  saved: boolean;
  path: string;
  state: string;
  needs_rebuild: boolean;
}

/**
 * Editor YAML del bloque `fabric:` de network.yaml.
 *
 * - Carga el bloque actual (credenciales enmascaradas `__REDACTED__`).
 * - Valida y guarda vía PUT /api/fabric/config (merge en el documento
 *   completo; backup .bak automático).
 * - Tras guardar avisa si el estado es `deployed`: el manifiesto nuevo
 *   se aplicará en el próximo Rebuild, no al despliegue vivo.
 */
export function FabricConfigEditor({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved?: () => void;
}) {
  const [content, setContent] = useState("");
  const [path, setPath] = useState("");
  const [loading, setLoading] = useState(true);
  const [saveResult, setSaveResult] = useState<SaveResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    apiGet<{ path: string; content: string }>("/api/fabric/config")
      .then((res) => {
        setContent(res.content);
        setPath(res.path);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "No se pudo cargar el manifiesto");
      })
      .finally(() => setLoading(false));
  }, []);

  async function save() {
    setSaving(true);
    setError(null);
    setSaveResult(null);
    try {
      const result = await apiPut<SaveResult>("/api/fabric/config", { content });
      setSaveResult(result);
      onSaved?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo guardar el manifiesto");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Portal>
      <div className="drawer-backdrop" style={{ zIndex: 90 }} onClick={onClose}>
        <aside
          className="event-drawer config-drawer"
          onClick={(event) => event.stopPropagation()}
          style={{ maxWidth: 860, display: "flex", flexDirection: "column" }}
        >
          <div className="drawer-head">
            <div>
              <span className="eyebrow">Fabric / manifiesto</span>
              <h2>
                Editar{" "}
                {path ? path.split("/").filter(Boolean).slice(-3).join("/") : "network.yaml"}
              </h2>
              <span className="mono muted">Se crea backup .bak en cada guardado</span>
            </div>
            <button className="icon-button" onClick={onClose} aria-label="Cerrar editor">
              <X size={18} />
            </button>
          </div>

        {loading && (
          <div className="empty-state small">
            <strong>Cargando manifiesto…</strong>
          </div>
        )}

        {error && (
          <div className="segment-note">
            <AlertTriangle size={15} />
            <p>{error}</p>
          </div>
        )}

        {saveResult?.saved && (
          <div className="segment-note" style={{ color: "var(--green, #4caf50)" }}>
            <CheckCircle2 size={15} />
            <p>
              Manifiesto guardado y validado (estado: {saveResult.state}).
              {saveResult.needs_rebuild && (
                <>
                  {" "}El fabric está <strong>desplegado</strong>: los cambios se
                  aplicarán en el próximo <strong>Rebuild</strong>.
                </>
              )}
            </p>
          </div>
        )}

        <textarea
          value={content}
          onChange={(event) => setContent(event.target.value)}
          spellCheck={false}
          style={{
            flex: 1,
            width: "100%",
            boxSizing: "border-box",
            minHeight: 380,
            fontFamily: "'JetBrains Mono', ui-monospace, monospace",
            fontSize: 12.5,
            background: "var(--bg-elev, #14181f)",
            color: "var(--text, #d8e0ea)",
            border: "1px solid var(--line, #2a3040)",
            borderRadius: 6,
            padding: 12,
            resize: "vertical",
          }}
        />

        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
          <button className="button ghost" onClick={onClose}>Cerrar</button>
          <button className="button primary" onClick={() => void save()} disabled={saving || loading}>
            {saving ? "Guardando…" : "Validar y guardar"}
          </button>
        </div>
        </aside>
      </div>
    </Portal>
  );
}
