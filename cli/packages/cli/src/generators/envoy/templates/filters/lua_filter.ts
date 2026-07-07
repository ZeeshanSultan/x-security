/**
 * envoy.filters.http.lua — residual x-security Lua filter.
 *
 * Only emitted when at least one endpoint declares a field with no native
 * equivalent (duplicateParamPolicy, headerInjectionGuard, request.signature,
 * etc.). The Lua source itself is built by ../lua.ts.
 */

export function emitLuaFilter(lines: string[], luaSource: string | null): void {
  if (!luaSource) return;
  lines.push('  - name: envoy.filters.http.lua');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua');
  lines.push('      # Residual x-security Lua — handles fields with no native filter equivalent');
  lines.push('      # (duplicateParamPolicy, headerInjectionGuard, request.signature, …).');
  lines.push('      inline_code: |');
  // Push the Lua source line-by-line so the outer per-line indent wrapper
  // (which adds 16 spaces to each entry) sees each Lua line individually.
  for (const ln of luaSource.replace(/\n$/, '').split('\n')) {
    lines.push(ln.length === 0 ? '        ' : '        ' + ln);
  }
}

export function emitRouterFilter(lines: string[]): void {
  lines.push('  - name: envoy.filters.http.router');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router');
}
