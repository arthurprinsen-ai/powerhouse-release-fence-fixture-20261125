// Review-only diagnostic contract. No provider access or credential processing.
const STAGES = Object.freeze(['first-run-gate','scope','key','jwt','app','installation','rules','pre-observe','issuance','permission','repository-scope','post-issue-observe','revocation','revocation-readback','final-observe','proof']);
const ISSUANCE = Object.freeze(['issuance','permission','repository-scope','post-issue-observe','revocation','revocation-readback','final-observe','proof']);
const codes = new Set(['SCOPE_DENIED','KEY_DENIED','APP_DENIED','INSTALLATION_DENIED','RULE_DENIED','BASE_DRIFT','PR_IDENTITY_DENIED','UNKNOWN_TOKEN_ISSUANCE','TOKEN_DENIED','PERMISSION_DENIED','TOKEN_SCOPE_DENIED','REVOCATION_FAILED','REVOCATION_READBACK_FAILED','PROOF_MISSING','ISSUANCE_HOLD']);
export function diagnostic(stage, error) {
 const known = STAGES.includes(stage);
 const code = typeof error?.message === 'string' && codes.has(error.message) ? error.message : 'UNCLASSIFIED';
 return Object.freeze({stage: known ? stage : 'unknown',code,issuanceUnresolved: !known || ISSUANCE.includes(stage),hold: true,mutationAuthority: false});
}
