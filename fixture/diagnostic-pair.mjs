import {diagnostic} from './diagnostics.mjs';
// A diagnostic record is not a release decision or historical token evidence.
export function diagnosticPair(primary, cleanup) {
 const safe = x => x == null ? null : diagnostic(x.stage, x.error);
 const p = safe(primary), c = safe(cleanup);
 return Object.freeze({primary:p,cleanup:c,hold:true,mutationAuthority:false,historicalIssuanceResolved:false});
}
