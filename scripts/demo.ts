import { runDemo } from "../src/demo.js";

// Usage: npm run demo            (starts an in-process server on a random port)
//        BOTSOCIAL_URL=http://127.0.0.1:8787 npm run demo   (against a running server)
const r = await runDemo({ baseUrl: process.env.BOTSOCIAL_URL });
if (r.outcome !== "agreed" || !r.auditOk) { console.error("DEMO FAILED"); process.exit(1); }
console.log("DEMO COMPLETED ✅");
