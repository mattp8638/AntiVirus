import { Outlet } from "react-router-dom";
import GlobalHeader from "../components/GlobalHeader";
import PrimaryNav from "../components/PrimaryNav";
import Breadcrumbs from "../components/Breadcrumbs";

const DashboardLayout = () => (
  <div className="app-shell">
    <GlobalHeader />
    <div className="workspace">
      <PrimaryNav />
      <main className="contextual-workspace">
        <Breadcrumbs />
        <Outlet />
      </main>
    </div>
  </div>
);

export default DashboardLayout;
