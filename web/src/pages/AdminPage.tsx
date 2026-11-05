import { useState } from "react";
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
import { ActionDialog } from "../components/ActionDialog";
import { useToast } from "../components/Toast";
import { API_KEYS, USERS } from "../data/mock";

type AdminDialog = "invite" | "rotate" | "manage" | "create-key" | null;

export function AdminPage() {
  const { notify } = useToast();
  const [users, setUsers] = useState(USERS);
  const [keys, setKeys] = useState(API_KEYS);
  const [dialog, setDialog] = useState<AdminDialog>(null);
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [inviteName, setInviteName] = useState("");
  const [inviteRole, setInviteRole] = useState("viewer");
  const [keyName, setKeyName] = useState("");

  function invite() {
    if (!inviteName.trim()) {
      notify("Escribe un nombre de usuario.", "error");
      return;
    }
    setUsers((current) => [...current, { username: inviteName.trim(), role: inviteRole, lastLogin: "nunca", status: "invitado" }]);
    notify(`Invitación preparada para ${inviteName.trim()} con rol ${inviteRole}.`, "success");
    setInviteName("");
    setDialog(null);
  }

  function rotate() {
    notify(dialog === "rotate" ? "Rotación de clave solicitada. Requiere confirmación del operador." : "Clave rotada en el espacio local de demostración.", "success");
    setDialog(null);
  }

  function createKey() {
    if (!keyName.trim()) {
      notify("Escribe un nombre para la API key.", "error");
      return;
    }
    setKeys((current) => [...current, { name: keyName.trim(), role: "writer", created: "ahora", scope: "sqlite:deception_events", status: "simulada" }]);
    notify(`API key ${keyName.trim()} creada en modo demostración.`, "success");
    setKeyName("");
    setDialog(null);
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow="Gobierno / Administration"
        title="Administración"
        description="Usuarios, roles, claves de API y postura de seguridad de la interfaz. Las acciones sensibles requieren autorización explícita."
        actions={
          <>
            <button className="button ghost" onClick={() => setDialog("rotate")}><RotateCcw size={15} /> Rotar clave</button>
            <button className="button primary" onClick={() => setDialog("invite")}><UserPlus size={15} /> Invitar usuario</button>
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
                {users.map((user) => (
                  <tr key={user.username}>
                    <td><span className="user-cell"><span className="avatar tiny"><Users size={13} /></span><strong>{user.username}</strong></span></td>
                    <td><span className={`role-pill role-${user.role}`}>{user.role}</span></td>
                    <td>{user.lastLogin}</td>
                    <td><span className={`health-pill ${user.status === "activo" ? "healthy" : "offline"}`}><i />{user.status}</span></td>
                    <td><button className="link-button" onClick={() => { setSelectedUser(user.username); setDialog("manage"); }}>Gestionar</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-footer-link"><button className="link-button" onClick={() => setDialog("invite")}><UserPlus size={14} /> Añadir cuenta</button></div>
        </Panel>

        <Panel className="span-4" eyebrow="Postura" title="Seguridad de la sesión">
          <div className="security-list">
            <div><ShieldCheck size={16} /><p><strong>JWT verificado</strong><span>Token de usuario con rol y versión de credencial.</span></p><CheckCircle2 size={15} className="ok" /></div>
            <div><LockKeyhole size={16} /><p><strong>Cookie y secretos</strong><span>La API key del writer nunca llega al navegador.</span></p><CheckCircle2 size={15} className="ok" /></div>
            <div><KeyRound size={16} /><p><strong>RBAC</strong><span>viewer, analyst, operator y admin.</span></p><CheckCircle2 size={15} className="ok" /></div>
            <div><Users size={16} /><p><strong>MFA</strong><span>Pendiente de implementación en el control plane.</span></p><span className="pending-pill">pendiente</span></div>
          </div>
        </Panel>

        <Panel className="span-12" eyebrow="Integraciones" title="Claves de API" description="Credenciales de servicio para ingesta y lectura local." flush>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Nombre</th><th>Rol</th><th>Scope</th><th>Creada</th><th>Estado</th><th aria-label="Acciones" /></tr></thead>
              <tbody>
                {keys.map((key) => (
                  <tr key={key.name}>
                    <td><span className="key-name"><KeyRound size={14} /><strong className="mono">{key.name}</strong></span></td>
                    <td><span className="role-pill">{key.role}</span></td>
                    <td className="mono muted">{key.scope}</td>
                    <td>{key.created}</td>
                    <td><span className="health-pill healthy"><i />{key.status}</span></td>
                    <td><button className="link-button" onClick={() => { setKeyName(key.name); setDialog("rotate"); }}>Rotar</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-footer-link"><button className="link-button" onClick={() => setDialog("create-key")}><Plus size={14} /> Crear API key</button></div>
        </Panel>

        <Panel className="span-12" eyebrow="Sistema" title="Configuración de la interfaz" description="Parámetros que la web propia consume del control plane." flush>
          <div className="config-grid">
            <div><span>Entorno</span><strong>laboratory</strong><small className="mono">NETPULSE_ENV</small></div>
            <div><span>Almacén local</span><strong className="mono">deception_events / events</strong><small>SQLite · solo lectura</small></div>
            <div><span>Dashboard inicial</span><strong>deception-overview</strong><small>Dystopia Web</small></div>
            <div><span>Branding</span><strong>Dystopia</strong><small>Dystopia Web</small></div>
            <div><span>Autenticación</span><strong>JWT local</strong><small>bcrypt · 30 min</small></div>
            <div><span>Transporte</span><strong>HTTPS / proxy</strong><small>pendiente en producción</small></div>
          </div>
        </Panel>
      </div>

      <ActionDialog
        open={dialog === "invite"}
        title="Invitar usuario"
        description="Crea una cuenta local con rol mínimo. En este entorno la acción se refleja solo en la interfaz."
        confirmLabel="Preparar invitación"
        onConfirm={invite}
        onClose={() => setDialog(null)}
      >
        <label className="action-field"><span>Usuario</span><input value={inviteName} onChange={(event) => setInviteName(event.target.value)} placeholder="analista_02" /></label>
        <label className="action-field"><span>Rol</span><select value={inviteRole} onChange={(event) => setInviteRole(event.target.value)}><option value="viewer">viewer</option><option value="analyst">analyst</option><option value="operator">operator</option><option value="admin">admin</option></select></label>
      </ActionDialog>

      <ActionDialog
        open={dialog === "rotate"}
        title="Rotar credencial"
        description="La rotación real se ejecuta desde el control plane con confirmación del operador. Aquí se simula la solicitud."
        confirmLabel="Solicitar rotación"
        tone="danger"
        onConfirm={rotate}
        onClose={() => setDialog(null)}
      >
        <div className="action-note">No se muestra ni se genera ninguna clave en el navegador.</div>
      </ActionDialog>

      <ActionDialog
        open={dialog === "manage"}
        title={`Gestionar ${selectedUser ?? "usuario"}`}
        description="Vista de solo lectura del rol y estado de la cuenta. Los cambios reales requieren el control plane."
        confirmLabel="Cerrar"
        cancelLabel="Cerrar"
        onConfirm={() => setDialog(null)}
        onClose={() => setDialog(null)}
      >
        <div className="action-metrics">
          <div><span>Usuario</span><strong>{selectedUser ?? "—"}</strong></div>
          <div><span>Origen</span><strong>control plane</strong></div>
          <div><span>MFA</span><strong>pendiente</strong></div>
          <div><span>Sesión</span><strong>JWT local</strong></div>
        </div>
      </ActionDialog>

      <ActionDialog
        open={dialog === "create-key"}
        title="Crear API key"
        description="La clave se generaría en el control plane y se mostraría una sola vez. En modo demostración solo se añade a la tabla."
        confirmLabel="Crear key"
        onConfirm={createKey}
        onClose={() => setDialog(null)}
      >
        <label className="action-field"><span>Nombre</span><input value={keyName} onChange={(event) => setKeyName(event.target.value)} placeholder="sensor-cowrie-c2" /></label>
      </ActionDialog>
    </div>
  );
}
