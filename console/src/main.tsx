import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AppProvider } from "./app-context";
import { Root } from "./App";
import { ReauthDialog } from "./components/ui";
import "./styles.css";

// Installable app and instant start-up; see public/sw.js. Not in the Vite dev server.
if ("serviceWorker" in navigator && import.meta.env.PROD) {
  window.addEventListener("load", () => { navigator.serviceWorker.register("/sw.js").catch(() => undefined); });
}

createRoot(document.getElementById("root")!).render(
  <AppProvider>
    <BrowserRouter>
      <Root />
    </BrowserRouter>
    <ReauthDialog />
  </AppProvider>,
);
