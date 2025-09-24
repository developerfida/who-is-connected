import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Layout from "@/components/Layout";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import ConnectionHistory from "@/pages/ConnectionHistory";
import RemoteUserConnections from "@/pages/RemoteUserConnections";
import RecentConnections from "@/pages/RecentConnections";
import SystemMonitor from "@/pages/SystemMonitor";

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="history" element={<ConnectionHistory />} />
          <Route path="recent" element={<RecentConnections />} />
          <Route path="remote-users" element={<RemoteUserConnections />} />
          <Route path="settings" element={<div className="p-6"><div className="text-center text-xl">Security Settings - Coming Soon</div></div>} />
          <Route path="monitor" element={<SystemMonitor />} />
          <Route path="connection/:id" element={<div className="p-6"><div className="text-center text-xl">Connection Details - Coming Soon</div></div>} />
        </Route>
      </Routes>
    </Router>
  );
}
