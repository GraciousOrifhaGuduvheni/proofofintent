import { randomBytes } from "node:crypto";
import { createDashboardServer } from "./server.js";

const port = Number(process.env.PORT ?? 8787);
const dataDir = process.env.POI_DATA_DIR ?? ".poi-data";
const generated = !process.env.POI_ADMIN_KEY;
const adminKey = process.env.POI_ADMIN_KEY ?? randomBytes(16).toString("hex");

const { server } = createDashboardServer({ dataDir, adminKey });

// Bound to localhost only on purpose.
server.listen(port, "127.0.0.1", () => {
  console.log(`POI dashboard: http://127.0.0.1:${port}`);
  console.log(`Public key for gateways: ${dataDir}/public.pem`);
  if (generated) {
    console.log(`Admin key (new each start; set POI_ADMIN_KEY to fix it): ${adminKey}`);
  }
});
