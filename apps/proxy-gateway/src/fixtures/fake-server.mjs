// Minimal stand-in for an MCP server: answers every request and counts them.
import { createInterface } from "node:readline";

let count = 0;
const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const msg = JSON.parse(line);
  count++;
  if (msg.id !== undefined) {
    process.stdout.write(
      JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { reached: true, count } }) + "\n",
    );
  }
});
