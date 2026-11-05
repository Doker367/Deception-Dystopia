import { CornerDownRight, ExternalLink } from "lucide-react";
import type { EventRow } from "../types";
import { countryFlag, formatDateTime, formatTime } from "../lib/format";
import { SeverityBadge } from "./SeverityBadge";

export type EventColumn = "time" | "severity" | "event" | "source" | "sensor" | "device" | "proto";

interface EventTableProps {
  events: EventRow[];
  compact?: boolean;
  onOpen?: (event: EventRow) => void;
  visibleColumns?: EventColumn[];
}

const ALL_COLUMNS: EventColumn[] = ["time", "severity", "event", "source", "sensor", "device", "proto"];

export function EventTable({ events, compact = false, onOpen, visibleColumns = ALL_COLUMNS }: EventTableProps) {
  const visible = new Set(visibleColumns);

  if (events.length === 0) {
    return (
      <div className="empty-state">
        <CornerDownRight size={20} />
        <strong>Sin eventos para este filtro</strong>
        <span>Prueba con otra búsqueda o amplía el rango de tiempo.</span>
      </div>
    );
  }

  return (
    <div className={`event-table-wrap ${compact ? "compact" : ""}`}>
      <table className="event-table">
        <thead>
          <tr>
            {visible.has("time") && <th className="col-time">Hora</th>}
            {visible.has("severity") && <th className="col-severity">Severidad</th>}
            {visible.has("event") && <th>Evento</th>}
            {visible.has("source") && <th>Origen</th>}
            {visible.has("sensor") && <th>Sensor</th>}
            {visible.has("device") && <th>Dispositivo</th>}
            {visible.has("proto") && <th className="col-proto">Proto</th>}
            <th className="col-action" aria-label="Abrir" />
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} onClick={() => onOpen?.(event)} className={onOpen ? "clickable" : ""}>
              {visible.has("time") && <td className="col-time">
                <span className="mono">{formatTime(event.timestamp)}</span>
                <small>{formatDateTime(event.timestamp)}</small>
              </td>}
              {visible.has("severity") && <td className="col-severity"><SeverityBadge severity={event.severity} /></td>}
              {visible.has("event") && <td>
                <div className="event-kind">
                  <strong>{event.action}</strong>
                  <span className="mono">{event.kind}</span>
                </div>
              </td>}
              {visible.has("source") && <td>
                <div className="source-cell">
                  <span className="flag">{countryFlag(event.countryCode)}</span>
                  <div>
                    <strong className="mono">{event.source}</strong>
                    <small>{event.country}</small>
                  </div>
                </div>
              </td>}
              {visible.has("sensor") && <td><span className="sensor-chip">{event.sensor}</span></td>}
              {visible.has("device") && <td><span className="mono muted">{event.device}</span></td>}
              {visible.has("proto") && <td className="col-proto"><span className="proto-chip">{event.proto}</span></td>}
              <td className="col-action">
                {onOpen && <button className="row-open" aria-label={`Abrir ${event.id}`}><ExternalLink size={14} /></button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
