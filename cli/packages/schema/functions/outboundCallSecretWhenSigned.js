// v0.5 S-11 Spectral function: when an outboundCall declares a signatureAlgorithm
// other than 'none', it MUST also declare a secretRef. JSON Schema enforces this
// via allOf/if-then, but we mirror it as a Spectral rule for a more legible
// per-call error message in the lint output.

export default function outboundCallSecretWhenSigned(targetVal) {
  if (!Array.isArray(targetVal)) return;
  const errors = [];
  targetVal.forEach((call, idx) => {
    if (!call || typeof call !== 'object') return;
    const algo = call.signatureAlgorithm;
    if (algo && algo !== 'none' && !call.secretRef) {
      errors.push({
        message: `outboundCalls[${idx}] uses signatureAlgorithm="${algo}" but is missing secretRef`,
        path: ['outboundCalls', idx]
      });
    }
  });
  return errors.length > 0 ? errors : undefined;
}
