// npm-publish bundle entrypoint. The registry's lazy template-literal dynamic
// import (`./generators/${target}/index.js`) cannot be statically inlined by
// esbuild, so — like byo.ts does for bunkerweb — this entry pre-seeds ALL
// native generators before handing control to the full CLI. The `await
// import` (not a static import) guarantees the registrations run before
// x-security.ts evaluates and parses argv.
//
// This file is only used by scripts/bundle-npm.mjs. The normal dist build
// (dist/bin/x-security.js) is unaffected.

import { registerGenerator } from '../registry.js';
import { kongGenerator } from '../generators/kong/index.js';
import { corazaGenerator } from '../generators/coraza/index.js';
import { bunkerwebGenerator } from '../generators/bunkerweb/index.js';
import { openappsecGenerator } from '../generators/openappsec/index.js';
import { firewallGenerator } from '../generators/firewall/index.js';
import { envoyGenerator } from '../generators/envoy/index.js';

registerGenerator('kong', kongGenerator);
registerGenerator('coraza', corazaGenerator);
registerGenerator('bunkerweb', bunkerwebGenerator);
registerGenerator('openappsec', openappsecGenerator);
registerGenerator('firewall', firewallGenerator);
registerGenerator('envoy', envoyGenerator);

await import('./x-security.js');
