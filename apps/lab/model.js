const comparisons = {
  eq: (actual, expected) => actual === expected,
  gteq: (actual, expected) => actual >= expected,
  lteq: (actual, expected) => actual <= expected
};

export const comparisonLabels = { eq: 'ist gleich', gteq: 'mindestens', lteq: 'höchstens' };

export function checkedFacts(rule, testCase) {
  const facts = { ...testCase.facts };
  const signers = rule.checks.find(check => check.kind === 'distinct-signatures');
  if (signers && testCase.simulatedSignerResults) {
    const allowed = new Set(signers.configuration.signers.map(signer => signer.id));
    const confirmed = testCase.simulatedSignerResults.filter(result =>
      result.result === 'valid' && result.sameArtifact && allowed.has(result.signerId)
    );
    facts[signers.fact] = new Set(confirmed.map(result => result.signerId)).size;
  }
  return facts;
}

function httpsUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function configurationError(rule) {
  const signers = rule.checks.find(check => check.kind === 'distinct-signatures')?.configuration.signers;
  if (signers) {
    const identities = signers.map(signer => signer.id.trim());
    if (identities.some(id => !id) || new Set(identities).size !== signers.length) {
      return 'Jeder Signierer braucht eine eigene, eindeutige ID.';
    }
    for (const signer of signers) {
      if (signer.method === 'external' && !httpsUrl(signer.connector?.endpoint)) {
        return `${signer.displayName} braucht eine gültige HTTPS-Adresse für den Prüfdienst.`;
      }
      if (signer.method === 'local-x509' && !signer.trustProfile?.trim()) {
        return `${signer.displayName} braucht ein Vertrauensprofil.`;
      }
    }
  }
  const { mode, targetTemplate, destination, payload } = rule.output;
  if (mode === 'link' && (!targetTemplate?.includes('{continuation}') || !httpsUrl(targetTemplate))) {
    return 'Die Zielvorlage muss eine HTTPS-Adresse mit {continuation} sein.';
  }
  if (mode === 'forward' && (!httpsUrl(destination) || !payload?.trim())) {
    return 'Für die Weiterleitung fehlen eine gültige HTTPS-Adresse oder die Nutzdaten.';
  }
  return '';
}

export function evaluate(rule, testCase) {
  const facts = checkedFacts(rule, testCase);
  const trace = rule.odrl.permission[0].constraint.map(constraint => {
    const actual = facts[constraint.leftOperand];
    const expected = constraint.rightOperand;
    const compare = comparisons[constraint.operator];
    const state = !compare || typeof actual !== typeof expected || actual === null
      ? 'skip'
      : compare(actual, expected) ? 'pass' : 'fail';
    return { ...constraint, actual, state };
  });
  const error = configurationError(rule);
  let state = 'pass';
  if (error) state = 'skip';
  else if (trace.some(step => step.state === 'fail')) state = 'fail';
  else if (trace.some(step => step.state === 'skip')) state = 'skip';
  return { facts, trace, state, valid: state === 'pass', error };
}

export function responsePreview(rule, testCase, result) {
  const { mode, targetTemplate, destination, payload } = rule.output;
  const { valid, state } = result;
  if (mode === 'link') {
    const continuation = encodeURIComponent(testCase.simulatedContinuation ?? `example-${testCase.id}`);
    const body = valid ? { valid, redirectUrl: targetTemplate.replaceAll('{continuation}', continuation) } : { valid };
    return { status: 200, body };
  }
  if (mode === 'forward') {
    if (valid) return { status: 200, body: { destination, payload, wouldForward: true } };
    return { status: state === 'skip' ? 503 : 403, body: { wouldForward: false } };
  }
  return { status: 200, body: valid };
}
