import { app } from "./app";
import { raccsController } from "./routes/raccoons";
import { setPeerResolver } from "./lib/rateLimit";

app.use(raccsController);

const port = parseInt(process.env.PORT || "3000");

app.listen(port, () => {
  console.log(`raccApi is running on port ${port}`);
});

// TCP peer address for the rate limiter's client-IP resolution
setPeerResolver((request) => app.server?.requestIP(request)?.address);

// Bun runs as PID 1 in the container, where signals without a handler are ignored,
// so without this Swarm waits out the stop grace period and SIGKILLs (exit 137).
let shuttingDown = false;
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received, shutting down`);
    try {
      await app.stop();
    } finally {
      process.exit(0);
    }
  });
}
