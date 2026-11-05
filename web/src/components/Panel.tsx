import type { ReactNode } from "react";

interface PanelProps {
  title?: string;
  eyebrow?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  flush?: boolean;
  dense?: boolean;
}

export function Panel({
  title,
  eyebrow,
  description,
  actions,
  children,
  className = "",
  flush = false,
  dense = false,
}: PanelProps) {
  return (
    <section className={`panel ${dense ? "panel-dense" : ""} ${className}`.trim()}>
      {(title || actions) && (
        <header className="panel-head">
          <div>
            {eyebrow && <span className="eyebrow">{eyebrow}</span>}
            {title && <h2 className="panel-title">{title}</h2>}
            {description && <p className="panel-description">{description}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className={flush ? "panel-body panel-body-flush" : "panel-body"}>{children}</div>
    </section>
  );
}
