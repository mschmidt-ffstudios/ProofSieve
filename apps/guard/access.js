import { onLanguageChange, t } from '../shared/i18n.js';

const ENDPOINT = /^\/verify(?:\/[A-Za-z0-9_-]+)*$/;
const TOKEN = /^(?:[A-Za-z0-9_-]{43}|[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;
const TOKEN_LIMIT = 12 * 1024 - 'Bearer '.length;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DECISION_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const INPUT_LIMIT = 96 * 1024;
const WALLET_START = '{"action":"start"}';
const WALLET_SESSION_ID = /^[A-Za-z0-9_-]{43}$/;
const WALLET_REQUEST_URI = /^haip-vp:\/\/\?[^#\s]+$/;
const encoder = new TextEncoder();
const inputFormats = {
  odrl: ['JSON-Fakten (ODRL)', 'JSON facts (ODRL)'],
  shacl: ['RDF Turtle (SHACL)', 'RDF Turtle (SHACL)'],
  'sd-jwt': ['Kompaktes SD-JWT VC', 'Compact SD-JWT VC'],
  mdoc: ['mdoc IssuerSigned (Base64url)', 'mdoc IssuerSigned (Base64url)'],
  'jwt-vc': ['Kompaktes W3C JWT-VC', 'Compact W3C JWT-VC'],
  'vc-data-integrity': ['W3C VC mit Data Integrity (JSON)', 'W3C VC with Data Integrity (JSON)'],
  bundle: ['Nachweisbündel (JSON)', 'Proof bundle (JSON)'],
  document: ['Dokument und Signaturen (JSON)', 'Document and signature proofs (JSON)'],
  wallet: ['Wallet-Sitzung (JSON)', 'Wallet session (JSON)'],
};

export const selectEndpointText = ['Prüfendpunkt auswählen', 'Select a verification endpoint'];
export const unavailableEndpointText = [
  'Der verlinkte Prüfendpunkt ist für dieses Konto nicht verfügbar.',
  'The linked verification endpoint is unavailable for this account.',
];

const copy = {
  walletRateLimited: ['Das Wallet-Startlimit ist erreicht. Warte die angegebene Zeit ab.',
    'The wallet start limit has been reached. Wait for the indicated retry interval.'],
  endpointUnavailable: unavailableEndpointText,
  access: ['Zugriffsschutz', 'Access control'],
  heading: ['Bei ProofSieve anmelden', 'Sign in to ProofSieve'],
  loginIntro: ['Verwende den Token für deine Rolle und deine Prüfendpunkte.',
    'Use the token assigned to your role and verification endpoints.'],
  token: ['Zugriffstoken', 'Access token'],
  login: ['Anmelden', 'Sign in'],
  logout: ['Abmelden', 'Sign out'],
  retry: ['Verbindung erneut prüfen', 'Retry connection'],
  admin: ['Admin', 'Admin'],
  verifier: ['Prüfer', 'Verifier'],
  verifyHeading: ['Prüfendpunkt aufrufen', 'Call a verification endpoint'],
  verifyIntro: ['Wähle einen deiner freigegebenen Endpunkte und übergib die Prüfdaten.',
    'Select one of your permitted endpoints and submit the verification data.'],
  endpoint: ['Freigegebener Prüfendpunkt', 'Permitted verification endpoint'],
  format: ['Eingabeformat', 'Input format'],
  input: ['Prüfinput', 'Verification input'],
  operation: ['Vorgangsreferenz', 'Operation reference'],
  file: ['UTF-8-Datei laden', 'Load a UTF-8 file'],
  discardHandoff: ['Builder-Eingabe verwerfen', 'Discard Builder input'],
  handoffApplied: ['Eingabe aus dem Credential Builder übernommen.', 'Input from the Credential Builder loaded.'],
  signedDemoLoaded: ['Signiertes Test-Credential geladen. Starte die Prüfung am Server.',
    'Signed test credential loaded. Start verification on the server.'],
  inputCleared: ['Der Endpunkt erwartet ein anderes Format. Gib neue Prüfdaten ein.',
    'This endpoint requires a different format. Enter new verification data.'],
  verify: ['Am Server prüfen', 'Verify on server'],
  response: ['Serverantwort', 'Server response'],
  evidence: ['Signierte Evidenz herunterladen', 'Download signed evidence'],
  walletExpiry: ['Sitzung gültig bis', 'Session expires at'],
  walletStart: ['Wallet-Sitzung starten', 'Start wallet session'],
  walletComplete: ['Wallet-Präsentation prüfen', 'Check wallet presentation'],
  walletFinished: ['Wallet-Sitzung abgeschlossen', 'Wallet session finished'],
  walletOperationHint: ['Verwende für eine neue Sitzung eine neue Vorgangsreferenz.',
    'Use a new operation reference for a new session.'],
  walletOpen: ['In der Wallet öffnen', 'Open in wallet'],
  walletApproved: ['Freigabe für diesen Vorgang erteilt.', 'This operation is approved.'],
  walletStarted: ['Wallet-Sitzung gestartet. Öffne die Autorisierungsanfrage aus der Antwort in deiner Wallet.',
    'Wallet session started. Open the authorization request from the response in your wallet.'],
  walletPending: ['Die Wallet-Präsentation steht noch aus. Prüfe nach der Präsentation erneut.',
    'The wallet presentation is pending. Verify again after presenting.'],
  walletExpired: ['Die Wallet-Sitzung ist abgelaufen. Die Prüfung blieb unbestimmt.',
    'The wallet session expired. Verification is inconclusive.'],
  walletRejected: ['Der Wallet-Nachweis wurde abgelehnt.', 'The wallet presentation was rejected.'],
  walletPolicyDenied: ['Die Prüfregel hat den Vorgang abgelehnt.', 'The verification rule denied the operation.'],
  walletUnavailable: ['Die Wallet-Prüfung ist vorübergehend nicht verfügbar.',
    'Wallet verification is temporarily unavailable.'],
  walletEvidenceUnavailable: ['Die Speicherung des Prüfnachweises ist unbestätigt. Frage dieselbe Wallet-Sitzung erneut ab. Der Vorgang bleibt gesperrt.',
    'Evidence storage could not be confirmed. Retry completion for this same wallet session. The operation remains blocked.'],
  walletEvidenceRetry: ['Abschluss erneut abfragen', 'Retry completion'],
  walletEvidenceInterrupted: ['Der ursprüngliche Prüfnachweis konnte nicht bestätigt werden. Die gespeicherte Entscheidung ist unbestimmt. Der Vorgang bleibt gesperrt.',
    'The original evidence could not be confirmed. The recorded decision is inconclusive. The operation remains blocked.'],
  walletConflict: ['Die Wallet-Sitzung kann nicht abgeschlossen werden. Suche in Swagger unter GET /evidence mit demselben Endpunkt und Vorgang nach vorhandener Evidenz. Der Vorgang bleibt gesperrt.',
    'The wallet session cannot be completed. In Swagger, look for existing evidence under GET /evidence with the same endpoint and operation. The operation remains blocked.'],
  verifiedAllow: ['Die Prüfung hat den Vorgang freigegeben.', 'Verification approved the operation.'],
  verifiedDeny: ['Die Prüfregel hat den Vorgang abgelehnt.', 'The verification rule denied the operation.'],
  verifiedCredentialRejected: ['Der Nachweis wurde bei der Vorprüfung abgelehnt.', 'Credential verification rejected the proof.'],
  verifiedIndeterminate: ['Die Prüfung blieb unbestimmt. Der Vorgang bleibt gesperrt.',
    'Verification is inconclusive. The operation remains blocked.'],
  deliveryConfirmed: ['Der Vorgang wurde freigegeben und weitergeleitet.', 'The operation was approved and forwarded.'],
  deliveryUnconfirmed: ['Die Regel hat freigegeben. Die Weiterleitung ist unbestätigt.',
    'The policy approved the operation. Delivery is unconfirmed.'],
  deliveryRejected: ['Die Regel hat freigegeben. Der Zieldienst hat die Weiterleitung abgelehnt.',
    'The policy approved the operation. The destination rejected delivery.'],
  checking: ['Zugriff wird geprüft …', 'Checking access …'],
  signingIn: ['Token wird geprüft …', 'Checking token …'],
  unavailable: ['Der Zugriffsdienst ist nicht erreichbar.', 'The access service is unavailable.'],
  invalidToken: ['Der Zugriffstoken ist ungültig oder wurde entzogen.', 'The access token is invalid or has been revoked.'],
  noEndpoints: ['Für diesen Zugang ist aktuell kein Prüfendpunkt freigegeben.',
    'No verification endpoint is currently available for this account.'],
  invalidInput: ['Gib ein gültiges JSON-Objekt ein.', 'Enter a valid JSON object.'],
  emptyInput: ['Gib Prüfdaten ein oder lade eine Datei.', 'Enter verification data or load a file.'],
  invalidOperation: ['Gib eine gültige Vorgangsreferenz ein, zum Beispiel order-1042.',
    'Enter a valid operation reference, for example order-1042.'],
  largeInput: ['Die Prüfanfrage überschreitet 96 KiB.', 'The verification request exceeds 96 KiB.'],
  largeFile: ['Die Datei überschreitet 96 KiB.', 'The file exceeds 96 KiB.'],
  invalidFile: ['Die Datei konnte nicht als UTF-8-Text gelesen werden.', 'The file could not be read as UTF-8 text.'],
  verifying: ['Der Server prüft die Anfrage …', 'The server is checking the request …'],
  requestFailed: ['Die Prüfanfrage konnte nicht abgeschlossen werden.', 'The verification request could not be completed.'],
};

function accessRequest(path, { token, method = 'GET', body, signal } = {}) {
  const headers = new Headers({ Accept: 'application/json' });
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  return fetch(path, {
    method, headers, body, signal,
    mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
  });
}

export function hasEvidenceExport(spec) {
  return spec?.paths?.['/evidence']?.get?.operationId === 'exportEvidence';
}

export function createEvidenceDownload(button, feedback, getToken) {
  let available = false;
  let decision = null;
  let pending = null;
  let message = null;

  function render() {
    button.hidden = !available || !decision;
    button.disabled = Boolean(pending);
    feedback.hidden = button.hidden || !message;
    feedback.textContent = message ? t(...message) : '';
  }

  function clear() {
    pending?.abort();
    pending = decision = message = null;
    render();
  }

  button.addEventListener('click', async () => {
    const token = getToken();
    if (!available || !decision || pending || !token) return;
    const { caller, endpoint, operationId, decisionId, outcome, ruleVersion } = decision;
    const query = new URLSearchParams({ endpoint, operationId, decisionId });
    const controller = new AbortController();
    pending = controller;
    message = ['Evidenz wird geladen …', 'Loading evidence …'];
    render();
    try {
      const response = await accessRequest(`/evidence?${query}`, { token, signal: controller.signal });
      if (!response.ok) throw new Error('Evidence export unavailable');
      const contents = await response.text();
      if (pending !== controller) return;
      const bundle = JSON.parse(contents);
      const scope = bundle?.scope;
      const [entry] = Array.isArray(bundle?.decisions) ? bundle.decisions : [];
      if (scope?.caller !== caller || scope.endpoint !== endpoint || scope.operationId !== operationId
          || bundle.version !== 1 || bundle.truncated !== false || bundle.decisions?.length !== 1
          || entry?.decisionId !== decisionId || entry.outcome !== outcome
          || entry.ruleVersion !== ruleVersion || bundle.integrity?.algorithm !== 'Ed25519'
          || typeof bundle.integrity.signature !== 'string') {
        throw new Error('Unexpected evidence export');
      }
      const url = URL.createObjectURL(new Blob([contents], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `proofsieve-evidence-${decisionId}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      message = ['Signierte Evidenz heruntergeladen.', 'Downloaded signed evidence.'];
    } catch {
      if (pending === controller) message = ['Diese Evidenz ist nicht verfügbar.', 'This evidence is unavailable.'];
    } finally {
      if (pending === controller) {
        pending = null;
        render();
      }
    }
  });

  onLanguageChange(render);
  return {
    clear,
    setAvailable(value) {
      available = value;
      if (available) render();
      else clear();
    },
    offer(caller, endpoint, operationId, result) {
      if (!caller || !ENDPOINT.test(endpoint) || !OPERATION_ID.test(operationId)
          || result?.operationId !== operationId || typeof result.decisionId !== 'string' || !DECISION_ID.test(result.decisionId)
          || !['allow', 'deny', 'indeterminate'].includes(result.outcome) || typeof result.ruleVersion !== 'string') return;
      decision = { caller, endpoint, operationId, decisionId: result.decisionId,
        outcome: result.outcome, ruleVersion: result.ruleVersion };
      render();
    },
  };
}

const walletRequestErrors = new Set(['walletUnavailable', 'walletRateLimited', 'walletEvidenceUnavailable', 'walletConflict']);

function verificationStatusKey(status, result) {
  if (result?.stage === 'credential' || result?.reason === 'credential_rejected') return 'verifiedCredentialRejected';
  if (result?.outcome === 'indeterminate') return 'verifiedIndeterminate';
  if (result?.outcome === 'allow' && result.delivery) {
    if (status === 200 && result.delivery.state === 'delivered') return 'deliveryConfirmed';
    if (result.delivery.state === 'rejected') return 'deliveryRejected';
    return 'deliveryUnconfirmed';
  }
  if (status === 503) return 'verifiedIndeterminate';
  if (result === true || (status === 200 && result?.valid === true)) return 'verifiedAllow';
  if (result === false || result?.outcome === 'deny' || result?.valid === false) return 'verifiedDeny';
  return null;
}

function walletStatusKey(status, result) {
  if (status === 409 && ['wallet_session_conflict', 'wallet_rule_changed'].includes(result?.code)) return 'walletConflict';
  if (status === 200 && result?.outcome === 'allow') return 'walletApproved';
  if (status === 201 && result?.state === 'pending') return 'walletStarted';
  if (status === 202 && result?.state === 'pending') return 'walletPending';
  if (status === 503 && result?.reason === 'wallet_expired') return 'walletExpired';
  if (status === 503 && result?.reason === 'wallet_evidence_interrupted'
      && result.outcome === 'indeterminate' && result.valid === false) return 'walletEvidenceInterrupted';
  if (status === 503 && result?.code === 'evidence_unavailable') return 'walletEvidenceUnavailable';
  if (status === 503 && result?.code === 'wallet_unavailable') return 'walletUnavailable';
  if (status === 429 && result?.code === 'wallet_rate_limited') return 'walletRateLimited';
  if (status === 403 && result?.reason === 'wallet_rejected') return 'walletRejected';
  if (status === 403 && result?.reason === 'policy_denied') return 'walletPolicyDenied';
  return null;
}

export function walletMessage(status, result) {
  return copy[walletStatusKey(status, result)];
}

export function walletCompletionInput(result, operationId) {
  if (result?.state !== 'pending' || result.operationId !== operationId
      || typeof result.sessionId !== 'string' || !WALLET_SESSION_ID.test(result.sessionId)
      || typeof result.authorizationRequestUri !== 'string' || !WALLET_REQUEST_URI.test(result.authorizationRequestUri)) {
    return null;
  }
  return { action: 'complete', sessionId: result.sessionId };
}

export function createWalletDeadline(element, requestLink = null) {
  const time = element.querySelector('time');
  let session = null;

  function render() {
    if (requestLink) {
      requestLink.hidden = element.hidden || !session;
      if (requestLink.hidden) requestLink.removeAttribute('href');
      else requestLink.href = session.authorizationRequestUri;
    }
    if (element.hidden || !session) return;
    time.dateTime = session.expiresAt;
    time.textContent = new Intl.DateTimeFormat(document.documentElement.lang, {
      dateStyle: 'short', timeStyle: 'medium',
    }).format(new Date(session.expiresAt));
  }

  onLanguageChange(render);
  return {
    hide() {
      element.hidden = true;
      render();
    },
    reset() {
      session = null;
      element.hidden = true;
      render();
    },
    update(endpoint, requestBody, status, result) {
      const request = JSON.parse(requestBody);
      const key = walletStatusKey(status, result);
      if (status === 201 && walletCompletionInput(result, request.operationId)) {
        session = Number.isFinite(Date.parse(result.expiresAt)) ? {
          endpoint, operationId: result.operationId, id: result.sessionId, expiresAt: result.expiresAt,
          authorizationRequestUri: result.authorizationRequestUri,
        } : null;
        element.hidden = !session;
      } else if (key === 'walletPending' || key === 'walletUnavailable') {
        element.hidden = !(session && session.endpoint === endpoint && session.operationId === request.operationId
          && request.data?.action === 'complete' && session.id === request.data.sessionId);
      } else if (key === 'walletEvidenceUnavailable' || key === 'walletEvidenceInterrupted' || key === 'walletConflict') {
        session = null;
        element.hidden = true;
      }
      render();
    },
  };
}

function readPrincipal(body) {
  if (body?.enabled !== true || typeof body.id !== 'string'
      || !['admin', 'verifier'].includes(body.role) || !Array.isArray(body.endpoints)
      || !body.endpoints.every(path => typeof path === 'string' && ENDPOINT.test(path))) {
    throw new Error('Invalid access response');
  }
  return body;
}

function verificationProfiles(spec, endpoints) {
  const profiles = new Map();
  for (const path of endpoints) {
    const operation = spec?.paths?.[path]?.post;
    const kind = operation?.['x-proofsieve-input'];
    const request = operation?.requestBody?.content?.['application/json'];
    const required = request?.schema?.required;
    if (!Object.hasOwn(inputFormats, kind) || !Array.isArray(required) || !required.includes('data')) {
      throw new Error('Invalid verification endpoint metadata');
    }
    const examples = ['sd-jwt', 'mdoc'].includes(kind) ? request.examples : null;
    profiles.set(path, { kind, operationRequired: required.includes('operationId'), examples });
  }
  return profiles;
}

function verificationBody(value, profile, operation) {
  const text = ['sd-jwt', 'mdoc', 'jwt-vc'].includes(profile.kind) ? value.trim() : value;
  if (!text.trim()) return { error: 'emptyInput' };
  if (encoder.encode(text).length > INPUT_LIMIT) return { error: 'largeInput' };
  let payload = JSON.stringify(text);
  if (['odrl', 'document', 'wallet', 'vc-data-integrity', 'bundle'].includes(profile.kind)) {
    try {
      const parsed = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { error: 'invalidInput' };
    } catch {
      return { error: 'invalidInput' };
    }
    // Send the original text so the server can validate duplicate keys and numeric lexemes.
    payload = text;
  }
  if (profile.operationRequired && !OPERATION_ID.test(operation)) return { error: 'invalidOperation' };
  const reference = profile.operationRequired ? `,"operationId":${JSON.stringify(operation)}` : '';
  const body = `{"data":${payload}${reference}}`;
  return encoder.encode(body).length > INPUT_LIMIT ? { error: 'largeInput' } : { body };
}

export function createAccess(container, {
  onAccess, onLogout, requestedEndpoint, requestedExampleCase, selectEndpointInUrl, readHandoff, discardHandoff,
}) {
  container.classList.add('guard-access');
  container.innerHTML = `
    <p class="status guard-access-probe" role="status" data-access="probe"></p>
    <button type="button" data-access="retry" data-copy="retry" hidden></button>
    <section class="panel guard-access-login" aria-labelledby="guard-access-heading" data-access="login" hidden>
      <header><span class="step" data-copy="access"></span><h1 id="guard-access-heading" data-copy="heading"></h1></header>
      <div class="panel-body">
        <p class="muted" data-copy="loginIntro"></p>
        <form class="guard-access-form" autocomplete="off" data-access="login-form">
          <label><span data-copy="token"></span>
            <input type="password" data-access="token" required maxlength="${TOKEN_LIMIT}" autocomplete="off" autocapitalize="off" spellcheck="false">
          </label>
          <p class="status" role="status" data-access="login-status" hidden></p>
          <button class="primary" type="submit" data-access="login-button" data-copy="login"></button>
        </form>
      </div>
    </section>
    <div class="guard-access-account" data-access="account" hidden>
      <div><span class="step" data-access="role"></span><strong data-access="id"></strong></div>
      <button type="button" data-access="logout" data-copy="logout"></button>
    </div>
    <section class="panel guard-access-verifier" aria-labelledby="guard-access-verify-heading" data-access="verifier" hidden>
      <header><h1 id="guard-access-verify-heading" tabindex="-1" data-copy="verifyHeading"></h1></header>
      <div class="panel-body">
        <p class="muted" data-copy="verifyIntro"></p>
        <form class="guard-access-form" data-access="verify-form">
          <div class="guard-access-columns">
            <label><span data-copy="endpoint"></span><select data-access="endpoint" required></select></label>
            <label><span data-copy="format"></span><input type="text" data-access="format" readonly></label>
          </div>
          <p class="status" data-access="endpoint-status" role="status" hidden></p>
          <div class="guard-access-handoff" data-access="handoff" hidden>
            <p class="muted" role="status" data-access="handoff-message"></p>
            <button type="button" data-access="discard-handoff" data-copy="discardHandoff"></button>
          </div>
          <label data-access="operation-field" hidden><span data-copy="operation"></span>
            <input type="text" data-access="operation" maxlength="128" autocomplete="off" autocapitalize="off" spellcheck="false">
            <span class="muted" data-access="wallet-operation-hint" data-copy="walletOperationHint" hidden></span>
          </label>
          <label><span data-copy="input"></span>
            <textarea data-access="input" rows="8" spellcheck="false" autocomplete="off" autocapitalize="off" maxlength="98304"></textarea>
          </label>
          <div class="actions guard-access-actions">
            <label><span data-copy="file"></span><input type="file" data-access="file"></label>
            <button class="primary" type="submit" data-access="verify" data-copy="verify"></button>
          </div>
        </form>
        <p class="status" data-access="verify-status" role="status" hidden></p>
        <div class="result guard-access-result" aria-live="polite" data-access="result" hidden>
          <div class="result-title"><strong data-copy="response"></strong><code data-access="http-status"></code></div>
          <p class="muted result-detail" data-access="wallet-expiry" hidden><span data-copy="walletExpiry"></span> <time></time></p>
          <a class="response-link" data-access="wallet-open" data-copy="walletOpen" hidden></a>
          <pre data-access="response"></pre>
          <button class="result-detail" type="button" data-access="evidence" data-copy="evidence" hidden></button>
          <p class="muted result-detail" role="status" data-access="evidence-status" hidden></p>
        </div>
      </div>
    </section>`;

  const get = name => container.querySelector(`[data-access="${name}"]`);
  const input = get('input');
  const tokenInput = get('token');
  const endpoint = get('endpoint');
  const format = get('format');
  const operation = get('operation');
  const file = get('file');
  const messages = {};
  let principal = null;
  let token = null;
  let authRequest = null;
  let verifyRequest = null;
  let fileRevision = 0;
  let filePending = false;
  let profiles = new Map();
  let activeProfile = null;
  let preparedWalletInput = '';
  let walletFinished = false;
  const evidence = createEvidenceDownload(get('evidence'), get('evidence-status'), () => token);
  const walletDeadline = createWalletDeadline(get('wallet-expiry'), get('wallet-open'));

  function status(name, key, state) {
    messages[name] = key;
    const element = get(name);
    element.hidden = !key;
    element.dataset.state = state ?? 'info';
    element.textContent = key ? t(...copy[key]) : '';
  }

  function renderLanguage() {
    for (const element of container.querySelectorAll('[data-copy]')) {
      element.textContent = t(...copy[element.dataset.copy]);
    }
    const placeholder = endpoint.querySelector('option[value=""]');
    if (placeholder) placeholder.textContent = t(...selectEndpointText);
    if (principal) get('role').textContent = t(...copy[principal.role]);
    for (const [name, key] of Object.entries(messages)) {
      if (key) get(name).textContent = t(...copy[key]);
    }
    renderInputProfile();
  }

  function clearResult() {
    evidence.clear();
    walletDeadline.hide();
    get('result').hidden = true;
    get('http-status').textContent = '';
    get('response').textContent = '';
    status('verify-status', null);
  }

  function loginScreen(message) {
    get('login').hidden = false;
    get('login-button').disabled = false;
    status('login-status', message, 'error');
  }

  function resetWalletSession() {
    if (preparedWalletInput && input.value === preparedWalletInput) input.value = WALLET_START;
    preparedWalletInput = '';
    walletFinished = false;
    walletDeadline.reset();
  }

  function resetAccess() {
    authRequest?.abort();
    verifyRequest?.abort();
    authRequest = verifyRequest = null;
    fileRevision += 1;
    filePending = false;
    token = principal = null;
    evidence.setAvailable(false);
    resetWalletSession();
    activeProfile = null;
    profiles.clear();
    tokenInput.value = input.value = operation.value = file.value = '';
    endpoint.replaceChildren();
    status('endpoint-status', null);
    get('id').textContent = get('role').textContent = '';
    get('account').hidden = get('verifier').hidden = true;
    renderInputProfile();
    clearResult();
  }

  function renderInputProfile() {
    format.value = activeProfile ? t(...inputFormats[activeProfile.kind]) : '';
    const handoff = principal?.role === 'verifier' ? readHandoff() : null;
    get('handoff').hidden = !handoff;
    if (handoff) {
      const expected = t(...inputFormats[handoff.language]);
      get('handoff-message').textContent = t(
        `Eine Builder-Eingabe wartet. Wähle einen Endpunkt für ${expected} oder verwirf die Übergabe.`,
        `Builder input is waiting. Select an endpoint for ${expected} or discard the handoff.`,
      );
    }
    const blocked = !activeProfile || Boolean(handoff);
    input.disabled = file.disabled = blocked;
    get('operation-field').hidden = !activeProfile?.operationRequired;
    get('wallet-operation-hint').hidden = activeProfile?.kind !== 'wallet';
    operation.disabled = blocked || !activeProfile.operationRequired;
    operation.required = Boolean(activeProfile?.operationRequired);
    const verify = get('verify');
    let action = 'verify';
    if (activeProfile?.kind === 'wallet') {
      if (walletFinished) action = 'walletFinished';
      else if (messages['verify-status'] === 'walletEvidenceUnavailable') action = 'walletEvidenceRetry';
      else if (preparedWalletInput) action = 'walletComplete';
      else if (input.value === WALLET_START) action = 'walletStart';
    }
    verify.textContent = t(...copy[action]);
    verify.disabled = blocked || filePending || Boolean(verifyRequest) || walletFinished;
  }

  function selectVerifierEndpoint() {
    resetWalletSession();
    const nextProfile = profiles.get(endpoint.value);
    const changedFormat = activeProfile && activeProfile.kind !== nextProfile?.kind;
    const inputCleared = changedFormat && Boolean(input.value);
    if (changedFormat) input.value = '';
    activeProfile = nextProfile;
    operation.value = '';
    const handoff = readHandoff();
    const compatible = handoff && handoff.language === activeProfile?.kind;
    if (compatible) {
      input.value = handoff.text;
      discardHandoff();
    } else if (!handoff && activeProfile?.kind === 'wallet') {
      input.value = WALLET_START;
    }
    resetVerification();
    if (compatible) status('verify-status', 'handoffApplied');
    else if (!activeProfile && requestedEndpoint() === null) status('verify-status', 'noEndpoints');
    else if (inputCleared) status('verify-status', 'inputCleared');
  }

  function showVerifier(account, verifiedProfiles) {
    profiles = verifiedProfiles;
    const requested = requestedEndpoint();
    const unavailable = requested !== null && !profiles.has(requested);
    endpoint.replaceChildren(
      ...(unavailable ? [new Option(t(...selectEndpointText), '')] : []),
      ...account.endpoints.map(path => new Option(path, path)),
    );
    endpoint.value = unavailable ? '' : requested ?? account.endpoints[0] ?? '';
    endpoint.disabled = !account.endpoints.length;
    status('endpoint-status', unavailable ? 'endpointUnavailable' : null, 'error');
    const handoff = readHandoff();
    selectVerifierEndpoint();
    const exampleCase = requestedExampleCase();
    if (!handoff && requested === endpoint.value && ['original', 'tampered'].includes(exampleCase)) {
      const example = activeProfile?.examples?.[exampleCase]?.value?.data;
      if (typeof example === 'string' && example && encoder.encode(example).length <= INPUT_LIMIT) {
        input.value = example;
        status('verify-status', 'signedDemoLoaded');
      }
    }
    get('verifier').hidden = false;
    container.querySelector('#guard-access-verify-heading').focus();
  }

  async function start() {
    container.hidden = false;
    get('retry').hidden = true;
    status('probe', 'checking');
    authRequest?.abort();
    const controller = new AbortController();
    authRequest = controller;
    try {
      const response = await accessRequest('/auth/me', { signal: controller.signal });
      if (controller !== authRequest) return;
      if (response.status === 401) {
        loginScreen();
        return;
      }
      const body = await response.json();
      if (controller !== authRequest) return;
      if (!response.ok || body.enabled !== false) throw new Error('Invalid access response');
      container.hidden = true;
      await onAccess({ token: null, principal: body });
    } catch {
      if (controller !== authRequest) return;
      container.hidden = false;
      status('probe', 'unavailable', 'error');
      get('retry').hidden = false;
    } finally {
      if (controller === authRequest) {
        authRequest = null;
        if (get('retry').hidden) status('probe', null);
      }
    }
  }

  get('retry').addEventListener('click', start);

  get('login-form').addEventListener('submit', async event => {
    event.preventDefault();
    const candidate = tokenInput.value.trim();
    tokenInput.value = '';
    if (candidate.length > TOKEN_LIMIT || !TOKEN.test(candidate)) {
      status('login-status', 'invalidToken', 'error');
      return;
    }
    authRequest?.abort();
    const controller = new AbortController();
    authRequest = controller;
    get('login-button').disabled = true;
    status('login-status', 'signingIn');
    try {
      const response = await accessRequest('/auth/me', { token: candidate, signal: controller.signal });
      if (controller !== authRequest) return;
      if (response.status === 401 || response.status === 403) {
        loginScreen('invalidToken');
        return;
      }
      if (!response.ok) throw new Error('Access service unavailable');
      const account = readPrincipal(await response.json());
      let verifiedProfiles;
      let evidenceAvailable = false;
      if (account.role === 'verifier') {
        const spec = await accessRequest('/openapi.json', { token: candidate, signal: controller.signal });
        if (!spec.ok) throw new Error('Verification metadata unavailable');
        const metadata = await spec.json();
        verifiedProfiles = verificationProfiles(metadata, account.endpoints);
        evidenceAvailable = hasEvidenceExport(metadata);
      }
      if (controller !== authRequest) return;
      principal = account;
      token = candidate;
      evidence.setAvailable(evidenceAvailable);
      get('login').hidden = true;
      get('id').textContent = account.id;
      get('role').textContent = t(...copy[account.role]);
      get('account').hidden = false;
      if (account.role === 'admin') await onAccess({ token, principal });
      else showVerifier(account, verifiedProfiles);
    } catch {
      if (controller !== authRequest) return;
      resetAccess();
      onLogout();
      loginScreen('unavailable');
    } finally {
      if (controller === authRequest) authRequest = null;
    }
  });

  get('logout').addEventListener('click', () => {
    resetAccess();
    onLogout();
    loginScreen();
    tokenInput.focus();
  });

  window.addEventListener('pagehide', () => {
    if (!principal && get('login').hidden) return;
    resetAccess();
    onLogout();
    loginScreen();
  });

  function resetVerification() {
    verifyRequest?.abort();
    verifyRequest = null;
    fileRevision += 1;
    filePending = false;
    clearResult();
    renderInputProfile();
  }

  endpoint.addEventListener('change', () => {
    if (!profiles.has(endpoint.value)) return;
    endpoint.querySelector('option[value=""]')?.remove();
    selectEndpointInUrl(endpoint.value);
    status('endpoint-status', null);
    selectVerifierEndpoint();
  });
  get('discard-handoff').addEventListener('click', () => {
    discardHandoff();
    resetVerification();
  });
  function resetInput() {
    resetWalletSession();
    resetVerification();
  }

  input.addEventListener('input', resetInput);
  operation.addEventListener('input', resetInput);

  file.addEventListener('change', async () => {
    const selected = file.files[0];
    file.value = '';
    if (!selected || principal?.role !== 'verifier' || !activeProfile || readHandoff()) return;
    resetInput();
    const revision = fileRevision;
    if (selected.size > INPUT_LIMIT) {
      status('verify-status', 'largeFile', 'error');
      return;
    }
    filePending = true;
    renderInputProfile();
    try {
      const value = new TextDecoder('utf-8', { fatal: true }).decode(await selected.arrayBuffer());
      if (revision === fileRevision) input.value = value;
    } catch {
      if (revision === fileRevision) status('verify-status', 'invalidFile', 'error');
    } finally {
      if (revision === fileRevision) {
        filePending = false;
        renderInputProfile();
      }
    }
  });

  get('verify-form').addEventListener('submit', async event => {
    event.preventDefault();
    const path = endpoint.value;
    if (get('verify').disabled || !activeProfile || readHandoff() || verifyRequest || principal?.role !== 'verifier'
        || !principal.endpoints.includes(path)) return;
    resetVerification();
    const reference = operation.value.trim();
    const { body, error } = verificationBody(input.value, activeProfile, reference);
    if (error) {
      status('verify-status', error, 'error');
      return;
    }
    const controller = new AbortController();
    verifyRequest = controller;
    get('verify').disabled = true;
    status('verify-status', 'verifying');
    try {
      const response = await accessRequest(path, { token, method: 'POST', body, signal: controller.signal });
      const result = await response.text();
      if (controller !== verifyRequest) return;
      status('verify-status', null);
      get('http-status').textContent = `HTTP ${response.status}`;
      get('response').textContent = result;
      get('result').hidden = false;
      let decision;
      try { decision = JSON.parse(result); } catch { return; }
      evidence.offer(principal.id, path, reference, decision);
      if (activeProfile.kind === 'wallet') {
        const key = walletStatusKey(response.status, decision);
        if (response.status === 201) {
          const completion = walletCompletionInput(decision, reference);
          if (!completion) {
            status('verify-status', 'requestFailed', 'error');
            return;
          }
          preparedWalletInput = JSON.stringify(completion, null, 2);
          input.value = preparedWalletInput;
        }
        if (key && !walletRequestErrors.has(key) && decision?.operationId !== reference) {
          status('verify-status', 'requestFailed', 'error');
          return;
        }
        walletFinished = key === 'walletConflict' || (decision?.operationId === reference && typeof decision.decisionId === 'string'
          && DECISION_ID.test(decision.decisionId) && ['allow', 'deny', 'indeterminate'].includes(decision.outcome));
        walletDeadline.update(path, body, response.status, decision);
        if (key) status('verify-status', key, key === 'walletApproved' ? 'success'
          : walletRequestErrors.has(key) ? 'error' : 'info');
      } else {
        const key = verificationStatusKey(response.status, decision);
        if (key) status('verify-status', key,
          key === 'verifiedAllow' || key === 'deliveryConfirmed' ? 'success' : 'info');
      }
    } catch {
      if (controller === verifyRequest) status('verify-status', 'requestFailed', 'error');
    } finally {
      if (controller === verifyRequest) {
        verifyRequest = null;
        renderInputProfile();
      }
    }
  });

  onLanguageChange(renderLanguage);
  renderLanguage();
  return { start };
}
