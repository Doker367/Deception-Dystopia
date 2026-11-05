import type { ReactNode } from "react";
import { X } from "lucide-react";

interface ActionDialogProps {
  open: boolean;
  title: string;
  description?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "primary" | "danger";
  onConfirm: () => void;
  onClose: () => void;
  children?: ReactNode;
}

export function ActionDialog({
  open,
  title,
  description,
  confirmLabel = "Confirmar",
  cancelLabel = "Cancelar",
  tone = "primary",
  onConfirm,
  onClose,
  children,
}: ActionDialogProps) {
  if (!open) return null;

  return (
    <div className="action-backdrop" onMouseDown={onClose}>
      <div className="action-dialog" role="dialog" aria-modal="true" aria-labelledby="action-title" onMouseDown={(event) => event.stopPropagation()}>
        <button className="icon-button action-close" onClick={onClose} aria-label="Cerrar"><X size={17} /></button>
        <span className="eyebrow">Dystopia action</span>
        <h2 id="action-title">{title}</h2>
        {description && <p>{description}</p>}
        {children && <div className="action-body">{children}</div>}
        <div className="action-actions">
          <button className="button ghost" onClick={onClose}>{cancelLabel}</button>
          <button className={`button ${tone === "danger" ? "danger" : "primary"}`} onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
