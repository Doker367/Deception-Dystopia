import { useEffect, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { OverviewPage } from "./pages/Overview";
import { MapPage } from "./pages/MapPage";
import { EventsPage } from "./pages/EventsPage";
import { HoneypotsPage } from "./pages/HoneypotsPage";
import { DevicesPage } from "./pages/DevicesPage";
import { FabricPage } from "./pages/FabricPage";
import { IngestPage } from "./pages/IngestPage";
import { AiPage } from "./pages/AiPage";
import { AdminPage } from "./pages/AdminPage";
import { AttackerDrawer } from "./components/AttackerDrawer";
import { useAnalytics } from "./data/useAnalytics";
import { LoginDialog } from "./components/LoginDialog";
import { UNAUTHORIZED_EVENT, clearToken, getToken } from "./lib/api";
import { useTheme } from "./lib/theme";
import type { PageId } from "./types";

const PAGES: PageId[] = ["overview", "map", "events", "honeypots", "devices", "fabric", "ingest", "ai", "admin"];

function pageFromHash(): PageId {
  const hash = window.location.hash.replace("#", "") as PageId;
  return PAGES.includes(hash) ? hash : "overview";
}

export function App() {
  const [page, setPage] = useState<PageId>(pageFromHash);
  const [range, setRange] = useState("24h");
  const [search, setSearch] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [attackerIp, setAttackerIp] = useState<string | null>(null);
  const [sessionActive, setSessionActive] = useState(() => Boolean(getToken()));
  const [theme, toggleTheme] = useTheme();
  const analytics = useAnalytics(range);

  useEffect(() => {
    const onHash = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [page]);

  useEffect(() => {
    const onUnauthorized = () => {
      setSessionActive(false);
      setLoginOpen(false);
      setAttackerIp(null);
    };
    const onStorage = (event: StorageEvent) => {
      if (event.key === "dystopia.access_token") setSessionActive(Boolean(getToken()));
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  function navigate(next: PageId) {
    setAttackerIp(null);
    if (next === page) {
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    window.location.hash = next;
    setPage(next);
  }

  function refresh() {
    setRefreshing(true);
    analytics.refresh();
    window.setTimeout(() => setRefreshing(false), 900);
  }

  function openEventsFor(query = "") {
    if (query) setSearch(query);
    navigate("events");
  }

  if (!sessionActive) {
    return (
      <div className="app login-gate">
        <LoginDialog
          open
          allowClose={false}
          onClose={() => {}}
          onSuccess={() => {
            setLoginOpen(false);
            setSessionActive(true);
            analytics.refresh();
          }}
        />
      </div>
    );
  }

  return (
    <div className="app">
      <Sidebar active={page} onNavigate={navigate} mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} dataMode={analytics.mode} collectorStatus={analytics.collectorHealth?.status ?? null} />
      <div className="workspace">
        <Topbar
          page={page}
          range={range}
          dataMode={analytics.mode}
          loading={analytics.loading}
          sessionActive={sessionActive}
          onLogin={() => setLoginOpen(true)}
          onLogout={() => {
            clearToken();
            setSessionActive(false);
            setAttackerIp(null);
            analytics.refresh();
          }}
          onRangeChange={setRange}
          search={search}
          onSearchChange={setSearch}
          onRefresh={refresh}
          refreshing={refreshing}
          theme={theme}
          onToggleTheme={toggleTheme}
          onOpenMobile={() => setMobileOpen(true)}
        />
        <main className="main">
          {page === "overview" && <OverviewPage search={search} range={range} data={analytics} onNavigate={navigate} />}
          {page === "map" && <MapPage search={search} origins={analytics.origins} unlocated={analytics.unlocated} mode={analytics.mode} onRefresh={analytics.refresh} onOpenEvents={(origin) => openEventsFor(origin.ip)} />}
          {page === "events" && <EventsPage search={search} range={range} events={analytics.events} total={analytics.totalEvents} mode={analytics.mode} onOpenAttacker={setAttackerIp} />}
          {page === "honeypots" && <HoneypotsPage onRefresh={analytics.refresh} onOpenEvents={openEventsFor} events={analytics.events} mode={analytics.mode} />}
          {page === "devices" && <DevicesPage />}
          {page === "fabric" && <FabricPage />}
          {page === "ingest" && <IngestPage />}
          {page === "ai" && <AiPage onOpenEvents={openEventsFor} />}
          {page === "admin" && <AdminPage />}
        </main>
      </div>
      <LoginDialog
        open={loginOpen}
        onClose={() => setLoginOpen(false)}
        onSuccess={() => {
          setLoginOpen(false);
          setSessionActive(true);
          analytics.refresh();
        }}
      />
      <AttackerDrawer source={attackerIp} mode={analytics.mode} sample={analytics.events} onClose={() => setAttackerIp(null)} />
    </div>
  );
}
