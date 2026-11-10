import { randomBytes } from "node:crypto";
import { createDashboardServer } from "./server.js";

const port = Number(process.env.PORT ?? 8787);
const dataDir = process.env.POI_DATA_DIR ?? ".poi-data";

const adminGenerated = !process.env.POI_ADMIN_KEY;
const gatewayGenerated = !process.env.POI_GATEWAY_KEY;
const adminKey = process.env.POI_ADMIN_KEY ?? randomBytes(16).toString("hex");
const gatewayKey = process.env.POI_GATEWAY_KEY ?? randomBytes(16).toString("hex");

if (adminKey.length < 16 || gatewayKey.length < 16) {
  console.error("POI_ADMIN_KEY and POI_GATEWAY_KEY must each be at least 16 characters.");
  process.exit(1);
}

const { server } = createDashboardServer({ dataDir, adminKey, gatewayKey });

// Bound to localhost only on purpose.
server.listen(port, "127.0.0.1", () => {
  console.log(`POI dashboard: http://127.0.0.1:${port}`);
  console.log(`Public key for gateways: ${dataDir}/public.pem`);
  if (adminGenerated) console.log(`Admin key (new each start): ${adminKey}`);
  if (gatewayGenerated) console.log(`Gateway key (new each start): ${gatewayKey}`);
  if (adminGenerated || gatewayGenerated) {
    console.log("Set POI_ADMIN_KEY / POI_GATEWAY_KEY to keep them stable.");
  }
});
