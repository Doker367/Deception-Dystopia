import {
  CheckCircle2,
  KeyRound,
  LockKeyhole,
  Plus,
  RotateCcw,
  ShieldCheck,
  UserPlus,
  Users,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { API_KEYS, USERS } from "../data/mock";

export function AdminPage() {
  return (
    <div className="page">
      <PageHeader
        eyebrow="Gobierno / Administration"
        title="Administración"
        description="Usuarios, roles, claves de API y postura de seguridad de la interfaz. Las acciones sensibles requieren autorización explícita."
        actions={
          <>
            <button className="button ghost"><RotateCcw size={15} /> Rotar clave</button>
            <button className="button primary"><UserPlus size={15} /> Invitar usuario</button>
          </>
        }
        meta={
          <>
            <span><i className="status-dot live" /> Sesión local</span>
            <span>rol administrador</span>
            <span className="mono">JWT · 30 min</span>
          </>
        }
      />

      <div className="admin-grid">
        <Panel className="span-8" eyebrow="Acceso" title="Usuarios" description="Cuentas locales del control plane y último acceso." flush>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Usuario</th><th>Rol</th><th>Último acceso</th><th>Estado</th><th aria-label="Acciones" /></tr></thead>
              <tbody>
                {USERS.map((user) => (
                  <tr key={user.username}>
                    <td><span className="user-cell"><span className="avatar tiny"><Users size={13} /></span><strong>{user.username}</strong></span></td>
                    <td><span className={`role-pill role-${user.role}`}>{user.role}</span></td>
                    <td>{user.lastLogin}</td>
                    <td><span className={`health-pill ${user.status === "activo" ? "healthy" : "offline"}`}><i />{user.status}</span></td>
                    <td><button className="link-button">Gestionar</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-footer-link"><button className="link-button"><UserPlus size={14} /> Añadir cuenta</button></div>
        </Panel>

        <Panel className="span-4" eyebrow="Postura" title="Seguridad de la sesión">
          <div className="security-list">
            <div><ShieldCheck size={16} /><p><strong>JWT verificado</strong><span>Token de usuario con rol y versión de credencial.</span></p><CheckCircle2 size={15} className="ok" /></div>
            <div><LockKeyhole size={16} /><p><strong>Cookie y secretos</strong><span>La API key del writer nunca llega al navegador.</span></p><CheckCircle2 size={15} className="ok" /></div>
            <div><KeyRound size={16} /><p><strong>RBAC</strong><span>viewer, analyst, operator y admin.</span></p><CheckCircle2 size={15} className="ok" /></div>
            <div><Users size={16} /><p><strong>MFA</strong><span>Pendiente de implementación en el control plane.</span></p><span className="pending-pill">pendiente</span></div>
          </div>
        </Panel>

        <Panel className="span-12" eyebrow="Integraciones" title="Claves de API" description="Credenciales de servicio para ingesta, lectura y Kibana." flush>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Nombre</th><th>Rol</th><th>Scope</th><th>Creada</th><th>Estado</th><th aria-label="Acciones" /></tr></thead>
              <tbody>
                {API_KEYS.map((key) => (
                  <tr key={key.name}>
                    <td><span className="key-name"><KeyRound size={14} /><strong className="mono">{key.name}</strong></span></td>
                    <td><span className="role-pill">{key.role}</span></td>
                    <td className="mono muted">{key.scope}</td>
                    <td>{key.created}</td>
                    <td><span className="health-pill healthy"><i />{key.status}</span></td>
                    <td><button className="link-button">Rotar</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-footer-link"><button className="link-button"><Plus size={14} /> Crear API key</button></div>
        </Panel>

        <Panel className="span-12" eyebrow="Sistema" title="Configuración de la interfaz" description="Parámetros que la web propia consume del control plane." flush>
          <div className="config-grid">
            <div><span>Entorno</span><strong>laboratory</strong><small className="mono">NETPULSE_ENV</small></div>
            <div><span>Data view</span><strong className="mono">deception-events*</strong><small>Elasticsearch 9.3.5</small></div>
            <div><span>Dashboard inicial</span><strong>deception-overview</strong><small>Dystopia Web</small></div>
            <div><span>Branding</span><strong>Dystopia</strong><small>inspirado en Kibana</small></div>
            <div><span>Autenticación</span><strong>JWT local</strong><small>bcrypt · 30 min</small></div>
            <div><span>Transporte</span><strong>HTTPS / proxy</strong><small>pendiente en producción</small></div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
