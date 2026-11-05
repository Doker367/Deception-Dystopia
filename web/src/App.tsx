import { useEffect, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { OverviewPage } from "./pages/Overview";
import { MapPage } from "./pages/MapPage";
import { EventsPage } from "./pages/EventsPage";
import { HoneypotsPage } from "./pages/HoneypotsPage";
import { DevicesPage } from "./pages/DevicesPage";
import { IngestPage } from "./pages/IngestPage";
import { AdminPage } from "./pages/AdminPage";
import { useAnalytics } from "./data/useAnalytics";
import { LoginDialog } from "./components/LoginDialog";
import { clearToken, getToken } from "./lib/api";
import type { PageId } from "./types";

const PAGES: PageId[] = ["overview", "map", "events", "honeypots", "devices", "ingest", "admin"];

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
  const [sessionActive, setSessionActive] = useState(() => Boolean(getToken()));
  const analytics = useAnalytics(range);

  useEffect(() => {
    const onHash = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [page]);

  function navigate(next: PageId) {
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

  return (
    <div className="app">
      <Sidebar active={page} onNavigate={navigate} mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} dataMode={analytics.mode} />
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
            analytics.refresh();
          }}
          onRangeChange={setRange}
          search={search}
          onSearchChange={setSearch}
          onRefresh={refresh}
          refreshing={refreshing}
          onOpenMobile={() => setMobileOpen(true)}
        />
        <main className="main">
          {page === "overview" && <OverviewPage search={search} range={range} data={analytics} onNavigate={navigate} />}
          {page === "map" && <MapPage search={search} origins={analytics.origins} mode={analytics.mode} onRefresh={analytics.refresh} onOpenEvents={(origin) => openEventsFor(origin.ip)} />}
          {page === "events" && <EventsPage search={search} range={range} events={analytics.events} total={analytics.totalEvents} mode={analytics.mode} />}
          {page === "honeypots" && <HoneypotsPage onRefresh={analytics.refresh} onOpenEvents={openEventsFor} />}
          {page === "devices" && <DevicesPage />}
          {page === "ingest" && <IngestPage />}
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
    </div>
  );
}
