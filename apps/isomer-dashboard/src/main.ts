/**
 * Process entrypoint for the Isomer verifier dashboard.
 */
import { env } from "node:process";
import { serveDashboard } from "./server.js";

serveDashboard({
  host: env.ISOMER_DASHBOARD_HOST ?? "127.0.0.1",
  port: Number(env.ISOMER_DASHBOARD_PORT ?? "8791")
});
