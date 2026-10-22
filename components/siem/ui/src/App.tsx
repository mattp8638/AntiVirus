import { Navigate, Route, Routes } from "react-router-dom";
import DashboardLayout from "./layouts/DashboardLayout";
import Overview from "./pages/Overview";
import Assets from "./pages/Assets";
import AssetDetail from "./pages/AssetDetail";
import Rmm from "./pages/Rmm";
import Siem from "./pages/Siem";
import DetectionEdr from "./pages/DetectionEdr";
import Vulnerabilities from "./pages/Vulnerabilities";
import PatchManagement from "./pages/PatchManagement";
import PenetrationTesting from "./pages/PenetrationTesting";
import PenTestDetail from "./pages/PenTestDetail";
import PsaWorkflows from "./pages/PsaWorkflows";
import PsaTicketDetail from "./pages/PsaTicketDetail";
import ComplianceAudit from "./pages/ComplianceAudit";
import Administration from "./pages/Administration";
import PatchDetail from "./pages/PatchDetail";

const App = () => (
  <Routes>
    <Route element={<DashboardLayout />}>
      <Route index element={<Navigate to="/overview" replace />} />
      <Route path="/overview" element={<Overview />} />
      <Route path="/assets" element={<Assets />} />
      <Route path="/assets/:assetId" element={<AssetDetail />} />
      <Route path="/rmm" element={<Rmm />} />
      <Route path="/siem" element={<Siem />} />
      <Route path="/detection-edr" element={<DetectionEdr />} />
      <Route path="/vulnerabilities" element={<Vulnerabilities />} />
      <Route path="/patch-management" element={<PatchManagement />} />
      <Route path="/patch-management/:patchId" element={<PatchDetail />} />
      <Route path="/penetration-testing" element={<PenetrationTesting />} />
      <Route path="/penetration-testing/:testId" element={<PenTestDetail />} />
      <Route path="/psa-workflows" element={<PsaWorkflows />} />
      <Route path="/psa-workflows/:ticketId" element={<PsaTicketDetail />} />
      <Route path="/compliance-audit" element={<ComplianceAudit />} />
      <Route path="/administration" element={<Administration />} />
    </Route>
  </Routes>
);

export default App;
