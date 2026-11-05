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
    window.setTimeout(() => setRefreshing(false), 900);
  }

  return (
    <div className="app">
      <Sidebar active={page} onNavigate={navigate} mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} />
      <div className="workspace">
        <Topbar
          page={page}
          range={range}
          onRangeChange={setRange}
          search={search}
          onSearchChange={setSearch}
          onRefresh={refresh}
          refreshing={refreshing}
          onOpenMobile={() => setMobileOpen(true)}
        />
        <main className="main">
          {page === "overview" && <OverviewPage search={search} range={range} onNavigate={navigate} />}
          {page === "map" && <MapPage search={search} />}
          {page === "events" && <EventsPage search={search} range={range} />}
          {page === "honeypots" && <HoneypotsPage />}
          {page === "devices" && <DevicesPage />}
          {page === "ingest" && <IngestPage />}
          {page === "admin" && <AdminPage />}
        </main>
      </div>
    </div>
  );
}
