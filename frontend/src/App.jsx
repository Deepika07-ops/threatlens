import DataCollection from "./DataCollection";
import SidebarNav from "./SidebarNav";
import ReportsPanel from "./ReportsPanel";
import DlpScanner from "./DlpScanner";
import ThreatTable from "./ThreatTable";
import { useEffect, useState } from "react";
import {
  Shield,
  LayoutDashboard,
  Activity,
  Database,
  FileSearch,
  FileText,
  Settings,
  Bell,
  Search,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowUpRight,
  Zap,
} from "lucide-react";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadDashboard = async () => {
    try {
      setLoading(true);

      const response = await fetch(`${API}/summary`);

      if (!response.ok) {
        throw new Error("Unable to connect");
      }

      const data = await response.json();
      setSummary(data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const total = summary?.total ?? 0;
  const high = summary?.by_severity?.High ?? 0;
  const medium = summary?.by_severity?.Medium ?? 0;
  const low = summary?.by_severity?.Low ?? 0;

  const pending = summary?.by_status?.Pending ?? 0;
  const approved = summary?.by_status?.Approved ?? 0;
  const rejected = summary?.by_status?.Rejected ?? 0;
  const escalated = summary?.by_status?.Escalated ?? 0;

  return (
    <div className="app">

      <SidebarNav />
      {/* SIDEBAR */}

      <aside className="sidebar">

        <div className="logo-area">
          <div className="logo-box">
            <Shield size={25} />
          </div>

          <div>
            <h1>ThreatLens</h1>
            <span>CYBER INTELLIGENCE</span>
          </div>
        </div>

        <div className="nav-title">
          MAIN MENU
        </div>

        <nav>

          <div className="nav-item active">
            <LayoutDashboard size={18} />
            Dashboard
          </div>

          <div className="nav-item">
            <Activity size={18} />
            Threat Intelligence
          </div>

          <div className="nav-item">
            <Database size={18} />
            Data Collection
          </div>

          <div className="nav-item">
            <FileSearch size={18} />
            Analyst Queue
          </div>

          <div className="nav-item">
            <Shield size={18} />
            DLP Scanner
          </div>

          <div className="nav-item">
            <FileText size={18} />
            Reports
          </div>

        </nav>

        <div className="nav-title bottom-title">
          SYSTEM
        </div>

        <div className="nav-item">
          <Settings size={18} />
          Settings
        </div>

        <div className="sidebar-bottom">

          <div className="security-status">

            <div className="online-icon">
              <Zap size={16} />
            </div>

            <div>
              <strong>System Secure</strong>
              <span>All services operational</span>
            </div>

          </div>

        </div>

      </aside>


      {/* MAIN CONTENT */}

      <main className="main">

        {/* TOP BAR */}

        <header className="topbar">

          <div className="breadcrumb">
            Security Operations Center
            <span>/</span>
            Overview
          </div>

          <div className="top-actions">

            <div className="search-box">
              <Search size={17} />
              <input placeholder="Search threats..." />
            </div>

            <button className="icon-button">
              <Bell size={19} />
              <span className="notification-dot"></span>
            </button>

            <div className="profile">
              <div className="profile-avatar">
                A
              </div>

              <div>
                <strong>Analyst</strong>
                <span>Security Team</span>
              </div>
            </div>

          </div>

        </header>


        {/* CONTENT */}

        <div className="content">

          {/* HERO */}

          <section className="hero">

            <div>

              <div className="live-label">
                <span></span>
                LIVE MONITORING
              </div>

              <h2>Threat Intelligence Overview</h2>

              <p>
                Monitor, analyze and prioritize cybersecurity threats
                across your environment.
              </p>

            </div>

            <button
              className="refresh-button"
              onClick={loadDashboard}
              disabled={loading}
            >
              <RefreshCw size={17} />
              {loading ? "Refreshing..." : "Refresh"}
            </button>

          </section>


          {/* STAT CARDS */}

          <section className="stats-grid">

            <div className="stat-card">

              <div className="stat-top">
                <span>Total Indicators</span>

                <div className="stat-icon blue">
                  <Activity size={19} />
                </div>
              </div>

              <div className="stat-number">
                {total}
              </div>

              <div className="stat-footer">
                <ArrowUpRight size={14} />
                Threat indicators collected
              </div>

            </div>


            <div className="stat-card danger">

              <div className="stat-top">
                <span>High Risk</span>

                <div className="stat-icon red">
                  <AlertTriangle size={19} />
                </div>
              </div>

              <div className="stat-number">
                {high}
              </div>

              <div className="stat-footer red-text">
                <AlertTriangle size={14} />
                Requires attention
              </div>

            </div>


            <div className="stat-card">

              <div className="stat-top">
                <span>Pending Review</span>

                <div className="stat-icon orange">
                  <Clock size={19} />
                </div>
              </div>

              <div className="stat-number">
                {pending}
              </div>

              <div className="stat-footer orange-text">
                <Clock size={14} />
                Analyst assessment required
              </div>

            </div>


            <div className="stat-card">

              <div className="stat-top">
                <span>Approved</span>

                <div className="stat-icon green">
                  <CheckCircle size={19} />
                </div>
              </div>

              <div className="stat-number">
                {approved}
              </div>

              <div className="stat-footer green-text">
                <CheckCircle size={14} />
                Cleared for sharing
              </div>

            </div>

          </section>


          {/* CHARTS */}

          <section className="dashboard-grid">

            {/* SEVERITY */}

            <div className="panel">

              <div className="panel-header">

                <div>
                  <h3>Threat Severity</h3>
                  <span>Indicator distribution</span>
                </div>

                <Activity size={19} />

              </div>

              <div className="severity-content">

                <div className="donut">

                  <div className="donut-center">
                    <strong>{total}</strong>
                    <span>Indicators</span>
                  </div>

                </div>

                <div className="legend">

                  <div className="legend-row">
                    <span className="legend-color high-color"></span>
                    <span>High</span>
                    <strong>{high}</strong>
                  </div>

                  <div className="legend-row">
                    <span className="legend-color medium-color"></span>
                    <span>Medium</span>
                    <strong>{medium}</strong>
                  </div>

                  <div className="legend-row">
                    <span className="legend-color low-color"></span>
                    <span>Low</span>
                    <strong>{low}</strong>
                  </div>

                </div>

              </div>

            </div>


            {/* ANALYST STATUS */}

            <div className="panel">

              <div className="panel-header">

                <div>
                  <h3>Analyst Workflow</h3>
                  <span>Current review status</span>
                </div>

                <FileSearch size={19} />

              </div>

              <div className="workflow">

                <div className="workflow-row">
                  <div className="workflow-label">
                    <span className="workflow-dot pending-dot"></span>
                    Pending
                  </div>
                  <strong>{pending}</strong>
                </div>

                <div className="workflow-bar">
                  <span
                    style={{
                      width: total ? `${(pending / total) * 100}%` : "0%",
                    }}
                  ></span>
                </div>


                <div className="workflow-row">
                  <div className="workflow-label">
                    <span className="workflow-dot approved-dot"></span>
                    Approved
                  </div>
                  <strong>{approved}</strong>
                </div>

                <div className="workflow-bar">
                  <span
                    className="approved-bar"
                    style={{
                      width: total ? `${(approved / total) * 100}%` : "0%",
                    }}
                  ></span>
                </div>


                <div className="workflow-row">
                  <div className="workflow-label">
                    <span className="workflow-dot rejected-dot"></span>
                    Rejected
                  </div>
                  <strong>{rejected}</strong>
                </div>

                <div className="workflow-bar">
                  <span
                    className="rejected-bar"
                    style={{
                      width: total ? `${(rejected / total) * 100}%` : "0%",
                    }}
                  ></span>
                </div>


                <div className="workflow-row">
                  <div className="workflow-label">
                    <span className="workflow-dot escalated-dot"></span>
                    Escalated
                  </div>
                  <strong>{escalated}</strong>
                </div>

                <div className="workflow-bar">
                  <span
                    className="escalated-bar"
                    style={{
                      width: total ? `${(escalated / total) * 100}%` : "0%",
                    }}
                  ></span>
                </div>

              </div>

            </div>

          </section>


          {/* THREAT FEED PREVIEW */}

          <section className="panel threat-panel">

            <div className="panel-header">

              <div>
                <h3>Threat Intelligence Feed</h3>
                <span>Recently collected indicators</span>
              </div>

              <button className="view-button">
                View all
                <ArrowUpRight size={15} />
              </button>

            </div>

            <ThreatTable onChanged={loadDashboard} />

          </section>


          {/* DATA COLLECTION */}
          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>Data Collection</h3>
                <span>Ingest threat feeds and score them automatically</span>
              </div>
            </div>
            <DataCollection onChanged={loadDashboard} />
          </section>

          {/* DLP SCANNER */}
          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>DLP Scanner</h3>
                <span>Detect and mask sensitive data before it leaves the system</span>
              </div>
            </div>
            <DlpScanner />
          </section>

          {/* REPORTS */}
          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>Reports and Sharing</h3>
                <span>Generate the PDF report and share approved intelligence</span>
              </div>
            </div>
            <ReportsPanel />
          </section>

          {/* BOTTOM TOOLS */}

          <section className="tools-grid">

            <div className="tool-card">

              <div className="tool-icon">
                <Shield size={21} />
              </div>

              <div>
                <h3>DLP Scanner</h3>
                <p>
                  Detect sensitive information before it leaves the system.
                </p>
              </div>

              <ArrowUpRight size={18} />

            </div>


            <div className="tool-card">

              <div className="tool-icon">
                <FileText size={21} />
              </div>

              <div>
                <h3>Threat Reports</h3>
                <p>
                  Generate intelligence reports for analysts.
                </p>
              </div>

              <ArrowUpRight size={18} />

            </div>


            <div className="tool-card">

              <div className="tool-icon">
                <Database size={21} />
              </div>

              <div>
                <h3>STIX Sharing</h3>
                <p>
                  Share approved intelligence using STIX 2.1.
                </p>
              </div>

              <ArrowUpRight size={18} />

            </div>

          </section>

        </div>

        <footer>
          <span>ThreatLens Intelligence Platform</span>
          <span>Â© 2026 â€¢ Secure Operations</span>
        </footer>

      </main>

    </div>
  );
}

export default App;




