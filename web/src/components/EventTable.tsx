import { CornerDownRight, ExternalLink } from "lucide-react";
import type { EventRow } from "../types";
import { countryFlag, formatDateTime, formatTime } from "../lib/format";
import { SeverityBadge } from "./SeverityBadge";

interface EventTableProps {
  events: EventRow[];
  compact?: boolean;
  onOpen?: (event: EventRow) => void;
}

export function EventTable({ events, compact = false, onOpen }: EventTableProps) {
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
            <th className="col-time">Hora</th>
            <th className="col-severity">Severidad</th>
            <th>Evento</th>
            <th>Origen</th>
            <th>Sensor</th>
            <th>Dispositivo</th>
            <th className="col-proto">Proto</th>
            <th className="col-action" aria-label="Abrir" />
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} onClick={() => onOpen?.(event)} className={onOpen ? "clickable" : ""}>
              <td className="col-time">
                <span className="mono">{formatTime(event.timestamp)}</span>
                <small>{formatDateTime(event.timestamp)}</small>
              </td>
              <td className="col-severity"><SeverityBadge severity={event.severity} /></td>
              <td>
                <div className="event-kind">
                  <strong>{event.action}</strong>
                  <span className="mono">{event.kind}</span>
                </div>
              </td>
              <td>
                <div className="source-cell">
                  <span className="flag">{countryFlag(event.countryCode)}</span>
                  <div>
                    <strong className="mono">{event.source}</strong>
                    <small>{event.country}</small>
                  </div>
                </div>
              </td>
              <td><span className="sensor-chip">{event.sensor}</span></td>
              <td><span className="mono muted">{event.device}</span></td>
              <td className="col-proto"><span className="proto-chip">{event.proto}</span></td>
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
