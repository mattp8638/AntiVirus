// Fenrir Console service worker: makes the console installable on phones and desktops and opens instantly.
// - Built assets (/assets/*, hashed names) are cached on first use and served from the cache.
// - Pages are network-first; with no connection the last copy of the app shell opens, which then shows
//   "You are offline" for anything that needs the server.
// - API calls, remote sessions, downloads and agent traffic are never cached.
const VERSION = "fenrir-console-v1";
const SHELL = ["/", "/manifest.webmanifest", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(VERSION).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== VERSION).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/dns/") || url.pathname.startsWith("/downloads/")) return;

  if (url.pathname.startsWith("/assets/")) {
    event.respondWith(
      caches.match(request).then((hit) => hit || fetch(request).then((response) => {
        if (response.ok) { const copy = response.clone(); caches.open(VERSION).then((cache) => cache.put(request, copy)); }
        return response;
      })),
    );
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).then((response) => {
        if (response.ok) { const copy = response.clone(); caches.open(VERSION).then((cache) => cache.put("/", copy)); }
        return response;
      }).catch(() => caches.match("/").then((hit) => hit || Response.error())),
    );
  }
});

// Notification clicks (alerts pushed to an installed console) open the linked page.
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
    for (const win of windows) { if ("focus" in win) { win.navigate(target); return win.focus(); } }
    return self.clients.openWindow(target);
  }));
});
