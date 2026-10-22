import { buildServer } from "./app.ts";

const port = Number(process.env.PORT ?? 4000);
const requestedHost = process.env.HOST?.trim();
const host = requestedHost && requestedHost.length > 0 ? requestedHost : "127.0.0.1";

const app = buildServer();

try {
  app.log.info({ host, port }, "Starting Fenrir feed service listener");
  await app.listen({ port, host });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
