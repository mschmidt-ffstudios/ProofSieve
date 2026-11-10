import { onLanguageChange, t } from '../shared/i18n.js';
import { createOdrlGraph } from './odrl-graph.js';
import { createRuleTester, verificationPath } from './rule-tester.js';
import {
  createAccess, createEvidenceDownload, createWalletDeadline, hasEvidenceExport,
  selectEndpointText, unavailableEndpointText, walletCompletionInput, walletMessage,
} from './access.js';

const get = id => document.getElementById(`guard-${id}`);
const editor = get('editor');
const openapi = get('openapi');

const language = get('language');
const policy = get('policy');
const mode = get('mode');
const data = get('data');
const save = get('save');
const reloadRule = get('reload-rule');
const verify = get('verify');
const testRule = get('test-rule');
const tester = createRuleTester(get('tester'));
const loadTemplate = get('load-template');
const loadNestedTemplate = get('nested-template');
const status = get('status');
const output = get('response');
const httpStatus = get('http-status');
const endpointPicker = get('endpoint-picker');
const endpointInput = get('endpoint');
const endpointField = get('endpoint-field');
const endpointBadge = get('endpoint-badge');
const resultEndpoint = get('result-endpoint');
const graphContainer = get('graph');
const graph = createOdrlGraph(graphContainer, text => {
  if (busy || readOnly) return;
  policy.value = text;
  onDraftChange();
}, () => {
  clearResponse();
  refreshControls();
  reportDraftState();
});
const raw = get('raw');
const rawTitle = get('raw-title');
const urls = get('urls');
const returnUrl = get('return-url');
const failUrl = get('fail-url');
const resultLink = get('response-link');
const handoff = get('handoff');
const handoffMessage = get('handoff-message');
const handoffKey = 'proofsieve:guard-input:v1';
const credentialPanel = get('credential');
const credentialExamples = get('credential-examples');
const validExample = get('example-valid');
const tamperedExample = get('example-tampered');
const inputCaption = get('input-caption');
const inputHelp = get('input-help');
const operationInput = get('operation');
const profile = get('document-profile');
const verification = get('verification');
const profileSummary = get('profile-summary');
const profileSigners = get('profile-signers');
const initialQuery = new URLSearchParams(location.search);
const requestEncoder = new TextEncoder();
const maxVerifyBody = 96 * 1024;
const operationPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const formatJson = value => JSON.stringify(value, null, 2);
const activeRuleMessage = ['Die gespeicherte Regel ist aktiv.', 'The saved rule is active.'];
const createEndpointText = ['+ Neuen Endpunkt anlegen', '+ Create an endpoint'];
const formats = {
  'sd-jwt': {
    title: 'EUDI SD-JWT VC',
    caption: ['Kompaktes SD-JWT VC', 'Compact SD-JWT VC'],
    description: [
      'Der Guard prüft die Aussteller-Signatur mit dem hinterlegten Schlüssel und bindet offengelegte Werte an die signierten Digests.',
      'The Guard verifies the issuer signature against the configured key and binds disclosed values to the signed digests.',
    ],
  },
  mdoc: {
    title: 'EUDI mdoc',
    caption: ['IssuerSigned als Base64url', 'Base64url-encoded IssuerSigned'],
    description: [
      'Der Guard prüft die COSE-Signatur des Mobile Security Object und die Digests der vorgelegten Datenelemente.',
      'The Guard checks the Mobile Security Object’s COSE signature and the digests of the supplied data elements.',
    ],
  },
  'jwt-vc': {
    title: 'W3C JWT-VC',
    caption: ['Kompaktes W3C JWT-VC', 'Compact W3C JWT-VC'],
    description: ['Der Guard prüft die ES256-Ausstellersignatur.',
      'The Guard verifies the ES256 issuer signature.'],
  },
  'vc-data-integrity': {
    title: 'W3C Data Integrity',
    caption: ['W3C VC als JSON', 'W3C VC as JSON'],
    description: ['Der Guard prüft einen eddsa-jcs-2022-Ausstellernachweis.',
      'The Guard verifies an eddsa-jcs-2022 issuer proof.'],
  },
};
const templates = {
  odrl: {
    policy: {
      '@context': ['http://www.w3.org/ns/odrl.jsonld', { field: 'https://proofsieve.example/facts/' }],
      '@type': 'Set',
      uid: 'urn:proofsieve:demo:active',
      profile: 'https://proofsieve.example/profiles/basic/v1',
      permission: [{
        target: 'urn:demo:service',
        action: 'use',
        constraint: [{ leftOperand: 'field:status', operator: 'eq', rightOperand: 'active' }],
      }],
    },
    data: formatJson({ status: 'active' }),
  },
  shacl: {
    policy: `@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <https://proofsieve.example/demo/> .

ex:Shape a sh:NodeShape ;
    sh:targetNode ex:request ;
    sh:property [
        sh:path ex:status ;
        sh:hasValue "active"
    ] .`,
    data: `@prefix ex: <https://proofsieve.example/demo/> .

ex:request ex:status "active" .`,
  },
};
const nestedTemplate = {
  policy: {
    ...templates.odrl.policy,
    uid: 'urn:proofsieve:demo:nested-access',
    permission: [{
      target: 'urn:demo:member-portal',
      action: 'use',
      constraint: [
        { leftOperand: 'field:status', operator: 'eq', rightOperand: 'active' },
        { or: [
          { leftOperand: 'field:role', operator: 'eq', rightOperand: 'admin' },
          { and: [
            { leftOperand: 'field:role', operator: 'eq', rightOperand: 'reviewer' },
            { leftOperand: 'field:mfa', operator: 'eq', rightOperand: true },
          ] },
        ] },
      ],
    }],
  },
  data: formatJson({ status: 'active', role: 'reviewer', mfa: true }),
};

let savedRule = null;
let savedRuleEtag = null;
let savedPolicyText = '';
let defaultInputText = '';
let savedVerificationText = '';
let capabilities = {};
let csrfToken = '';
let busy = false;
let activeEndpoint = '/verify';
let endpoints = [activeEndpoint];
let creating = false;
let unavailableEndpoint = false;
let conflictedEndpoint = null;
let builderInput = readBuilderInput();
let statusMessage = ['Regel wird geladen …', 'Loading rule …'];
let hasResult = false;
let walletRecoveryFinished = false;
let readOnly = false;
let examples = null;
let credentialResult = null;
let principal = null;
let bearer = null;
let editorSession = null;
const evidence = createEvidenceDownload(get('evidence'), get('evidence-status'), () => bearer);
const walletDeadline = createWalletDeadline(get('wallet-expiry'));

function allEndpoints() {
  return !principal?.enabled || principal.allEndpoints;
}

function newEndpointPath() {
  if (allEndpoints()) return '/verify/';
  return principal.grants.find(path => !endpoints.includes(path)) ?? '';
}

function readBuilderInput() {
  try {
    const item = JSON.parse(sessionStorage.getItem(handoffKey));
    if (['odrl', 'shacl'].includes(item?.language) && typeof item.text === 'string'
      && new TextEncoder().encode(item.text).length <= 64 * 1024) return item;
    sessionStorage.removeItem(handoffKey);
  } catch {
    // The Guard can still accept manually entered data.
  }
  return null;
}

function discardBuilderInput() {
  builderInput = null;
  handoff.hidden = true;
  try {
    sessionStorage.removeItem(handoffKey);
  } catch {
    // Keep the current page usable if browser storage is unavailable.
  }
}

function renderHandoffMessage() {
  if (!builderInput) return;
  const expectsJson = builderInput.language === 'odrl';
  handoffMessage.textContent = t(
    `Testdaten aus dem Credential Builder warten. Wähle oder speichere einen Endpunkt mit ${expectsJson ? 'ODRL für JSON-Fakten' : 'SHACL für Turtle'}.`,
    `Test data from the Credential Builder is waiting. Select or save an endpoint with ${expectsJson ? 'ODRL for JSON facts' : 'SHACL for Turtle'}.`,
  );
}

function useBuilderInput() {
  if (!builderInput) return false;
  if (savedRule.credential || savedRule.verification || savedRule.wallet || savedRule.bundle
      || builderInput.language !== savedRule.language) {
    renderHandoffMessage();
    handoff.hidden = false;
    return false;
  }
  data.value = builderInput.text;
  discardBuilderInput();
  return true;
}

function showActiveRule(resetInput, message, state = 'info', example = 'valid') {
  if (resetInput) {
    const exampleInput = savedRule.wallet ? '{"action":"start"}'
      : savedRule.credential || savedRule.verification || savedRule.bundle
      ? examples?.[example] ?? '' : templates[language.value].data;
    defaultInputText = builderInput ? '' : exampleInput;
    data.value = defaultInputText;
  }
  report(useBuilderInput() ? [
    'Testdaten aus dem Credential Builder übernommen. Du kannst sie jetzt prüfen.',
    'Test data from the Credential Builder is ready to verify.',
  ] : message, state);
}

function policyText(rule) {
  return rule.language === 'odrl' ? formatJson(rule.policy) : rule.policy;
}

function hasDraft() {
  return graph.hasPendingEdit() || !savedRule || language.value !== savedRule.language
    || mode.value !== savedRule.responseMode || policy.value !== savedPolicyText
    || verification.value.trim() !== savedVerificationText
    || (mode.value === 'url' && (returnUrl.value.trim() !== savedRule.returnUrl || failUrl.value.trim() !== savedRule.failUrl));
}

document.querySelector('header.top').addEventListener('click', event => {
  const link = event.target.closest('a[href^="/apps/"]');
  if (!link || event.defaultPrevented || event.button !== 0 || event.altKey || event.ctrlKey
      || event.metaKey || event.shiftKey || editor.hidden || unavailableEndpoint || !csrfToken || !hasDraft()) return;
  if (!window.confirm(t('Ungespeicherte Regel verwerfen und die Ansicht wechseln?',
    'Discard the unsaved rule and leave this view?'))) event.preventDefault();
});

function refreshControls() {
  const blocked = busy || unavailableEndpoint;
  const pendingCondition = graph.hasPendingEdit();
  endpointPicker.disabled = busy;
  for (const control of [data, operationInput, endpointInput, validExample, tamperedExample]) {
    control.disabled = blocked;
  }
  for (const control of [mode, loadTemplate, loadNestedTemplate, returnUrl, failUrl]) {
    control.disabled = blocked || readOnly;
  }
  if (savedRule?.responseMode === 'decision' && !allEndpoints()) mode.disabled = true;
  if (savedRule?.wallet || savedRule?.bundle) mode.disabled = loadTemplate.disabled = true;
  graphContainer.inert = blocked;
  loadNestedTemplate.hidden = language.value !== 'odrl' || !allEndpoints();
  endpointInput.readOnly = !allEndpoints();
  language.disabled = blocked || readOnly || pendingCondition || Boolean(savedRule?.credential || savedRule?.wallet || savedRule?.bundle);
  policy.readOnly = blocked || readOnly || pendingCondition;
  verification.readOnly = blocked || readOnly || capabilities.verification !== true;
  save.disabled = blocked || readOnly || pendingCondition || !csrfToken || Boolean(conflictedEndpoint);
  reloadRule.hidden = !conflictedEndpoint;
  reloadRule.disabled = busy;
  verify.disabled = blocked || !csrfToken || hasDraft() || walletRecoveryFinished
    || Boolean(builderInput || conflictedEndpoint);
  testRule.hidden = savedRule?.wallet === true;
  testRule.disabled = blocked || pendingCondition || !csrfToken || Boolean(builderInput || savedRule?.bundle || savedRule?.wallet);
}

function syncEndpoints() {
  endpointPicker.replaceChildren(
    ...(unavailableEndpoint ? [new Option(t(...selectEndpointText), '')] : []),
    ...endpoints.map(path => new Option(path, path)),
    ...(newEndpointPath() ? [new Option(t(...createEndpointText), '__new__')] : []),
  );
  endpointPicker.value = unavailableEndpoint ? '' : creating ? '__new__' : activeEndpoint;
  endpointField.hidden = !creating;
  syncEndpointLabels();
}

function syncEndpointLabels() {
  const path = unavailableEndpoint ? '' : creating ? endpointInput.value.trim() : activeEndpoint;
  endpointBadge.hidden = unavailableEndpoint;
  endpointBadge.textContent = path ? `POST ${path}` : t('Neuer Endpunkt', 'New endpoint');
  resultEndpoint.textContent = path || '/verify/…';
}

function report(message, state = 'info') {
  statusMessage = message;
  status.textContent = t(...statusMessage);
  status.dataset.state = state;
}

function clearResponse() {
  evidence.clear();
  walletDeadline.hide();
  hasResult = false;
  walletRecoveryFinished = false;
  credentialResult = null;
  renderCredentialFlow();
  renderEmptyResponse();
  httpStatus.textContent = '';
  resultLink.hidden = true;
  resultLink.removeAttribute('href');
}

function renderEmptyResponse() {
  if (!hasResult) output.textContent = t('Noch keine Prüfung ausgeführt.', 'No verification has run yet.');
}

function renderCredentialFlow() {
  const passedProof = credentialResult === 'allowed' || credentialResult === 'policy';
  const labels = {
    pending: ['Ausstehend', 'Pending'],
    passed: ['Bestätigt', 'Verified'],
    unconfirmed: ['Nicht bestätigt', 'Unconfirmed'],
    skipped: ['Nicht ausgeführt', 'Skipped'],
    allowed: ['Freigegeben', 'Allowed'],
    denied: ['Abgelehnt', 'Denied'],
  };
  const proofState = passedProof ? 'passed' : credentialResult === 'credential' ? 'unconfirmed' : 'pending';
  const policyStates = { allowed: 'allowed', policy: 'denied', credential: 'skipped' };
  const states = { signature: proofState, claims: proofState, policy: policyStates[credentialResult] ?? 'pending' };
  for (const [step, state] of Object.entries(states)) {
    const badge = credentialPanel.querySelector(`[data-step="${step}"] strong`);
    badge.dataset.state = state;
    badge.textContent = t(...labels[state]);
  }
}

function renderInputProfile() {
  const format = formats[savedRule?.credential?.format];
  credentialPanel.hidden = !format;
  credentialExamples.hidden = !examples;
  get('read-only').hidden = !readOnly;
  get('edit-actions').hidden = readOnly;
  get('policy-help').textContent = readOnly
    ? t('Dieser Regeltext gehört zum Demo-Endpunkt.', 'This rule text belongs to the demo endpoint.')
    : t('Hier steht der Regeltext, den der Server prüft und speichert.', 'The server validates and saves this rule text.');
  if (format) {
    get('credential-format').textContent = format.title;
    get('credential-description').textContent = t(...format.description);
    inputCaption.textContent = t(...format.caption);
    inputHelp.textContent = t(
      'Die ODRL-Regel erhält nur Claims aus dem geprüften Aussteller-Nachweis. Wallet-Bindung und Widerruf sind separate Prüfungen.',
      'The ODRL rule receives only claims from the verified issuer proof. Wallet binding and revocation are separate checks.',
    );
  } else if (savedRule?.wallet) {
    inputCaption.textContent = t('Wallet-Sitzung (JSON)', 'Wallet session (JSON)');
    inputHelp.textContent = t(
      'Starte die Sitzung mit einer Vorgangsreferenz. Öffne die Autorisierungsanfrage in der Wallet und prüfe die vorbereitete Abschlussanfrage mit derselben Referenz.',
      'Start the session with an operation reference. Open the authorization request in the wallet, then verify the prepared completion request with the same reference.',
    );
  } else if (savedRule?.bundle) {
    const items = Object.keys(savedRule.bundle.items).join(', ');
    inputCaption.textContent = t('Nachweisbündel', 'Proof bundle');
    inputHelp.textContent = t(`Gib die Nachweise als JSON für diese Felder ein. ${items}`,
      `Enter a JSON object with proofs for these fields. ${items}`);
  } else if (savedRule?.verification) {
    inputCaption.textContent = t('Dokument und Signaturnachweise', 'Document and signature proofs');
    inputHelp.textContent = t(
      'Gib ein JSON-Objekt mit dem Base64-Dokument in document und einer Liste proofs ein. Die Prüfung kann konfigurierte Prüfdienste aufrufen.',
      'Enter a JSON object with the Base64 document in document and a proofs list. Verification may contact configured check services.',
    );
  } else {
    inputCaption.textContent = t('Prüfinput', 'Input to verify');
    inputHelp.textContent = t('ODRL liest ein JSON-Objekt. SHACL prüft einen RDF-Graphen als Turtle.',
      'ODRL reads a JSON object. SHACL validates an RDF graph written in Turtle.');
  }
  renderCredentialFlow();
}

function applySavedRule({ rule, policyText: source, endpoint, endpoints: configuredEndpoints, readOnly: fixed,
  credentialExamples: samples, capabilities: available }, etag) {
  graph.resetEdit();
  capabilities = available ?? {};
  savedRule = rule;
  savedRuleEtag = etag;
  conflictedEndpoint = null;
  savedPolicyText = typeof source === 'string' ? source : policyText(rule);
  savedVerificationText = rule.verification ? formatJson(rule.verification) : '';
  verification.value = savedVerificationText;
  if (endpoint !== activeEndpoint) operationInput.value = '';
  readOnly = fixed === true;
  examples = samples && typeof samples.valid === 'string' && typeof samples.tampered === 'string' ? samples : null;
  activeEndpoint = endpoint;
  endpoints = configuredEndpoints;
  creating = false;
  unavailableEndpoint = false;
  language.value = rule.language;
  mode.value = rule.responseMode;
  policy.value = savedPolicyText;
  returnUrl.value = rule.returnUrl ?? '';
  failUrl.value = rule.failUrl ?? '';
  raw.open = language.value === 'shacl';
  syncEndpoints();
  renderPolicyEditor();
  renderInputProfile();
}

function renderVerificationProfile() {
  const value = verification.value.trim();
  profile.hidden = Boolean(savedRule?.credential || savedRule?.bundle)
    || (!savedVerificationText && capabilities.verification !== true);
  get('profile-help').textContent = capabilities.verification === true && !readOnly
    ? t(
      'Lege die Schwelle und Signierer mit ihren hinterlegten Zertifikaten und konfigurierten Connector-IDs fest. Ein leeres Profil entfernt die Dokumentprüfung. Nutze den ODRL-Entscheidungsmodus für Dokumentprofile.',
      'Set the threshold and signers with their pinned certificates and configured connector IDs. Leave the profile empty to remove it. Use ODRL decision mode for document profiles.',
    ) : t('Ein Admin mit Zugriff auf alle Endpunkte pflegt dieses Prüfprofil.',
      'An admin with access to all endpoints maintains this verification profile.');
  profileSigners.replaceChildren();
  if (!value) {
    profileSummary.textContent = t('Für diesen Entwurf ist keine Dokumentprüfung gesetzt.',
      'This draft has no document verification configured.');
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    profileSummary.textContent = t('Das Prüfprofil braucht gültiges JSON.', 'The verification profile requires valid JSON.');
    return;
  }
  if (!Number.isInteger(parsed?.threshold) || !Array.isArray(parsed?.signers) || parsed.signers.length > 8) {
    profileSummary.textContent = t('Lege eine Schwelle und bis zu acht Signierer fest.',
      'Set a threshold and up to eight signers.');
    return;
  }
  profileSummary.textContent = t(
    `Schwelle · ${parsed.threshold} von ${parsed.signers.length} bestätigten Signierern`,
    `Threshold · ${parsed.threshold} of ${parsed.signers.length} verified signers`,
  );
  for (const signer of parsed.signers) {
    if (typeof signer?.id !== 'string' || typeof signer.kind !== 'string') continue;
    const item = document.createElement('li');
    const label = document.createElement('strong');
    label.textContent = verificationPath(signer.kind);
    item.append(signer.id, label);
    if (typeof signer.connector === 'string') item.append(` · ${signer.connector}`);
    profileSigners.append(item);
  }
}

function renderPolicyEditor() {
  const isODRL = language.value === 'odrl';
  document.getElementById('policy-heading').textContent = creating
    ? t('Regelentwurf', 'Rule draft') : t('Aktive Regel', 'Active rule');
  graphContainer.hidden = !isODRL || !policy.value;
  rawTitle.textContent = isODRL
    ? readOnly ? t('ODRL-JSON-LD anzeigen', 'View ODRL JSON-LD') : t('ODRL-JSON-LD anzeigen und bearbeiten', 'View and edit ODRL JSON-LD')
    : t('SHACL-Turtle anzeigen und bearbeiten', 'View and edit SHACL Turtle');
  urls.hidden = mode.value !== 'url';
  mode.querySelector('option[value="decision"]').hidden = capabilities.decision !== true && mode.value !== 'decision';
  get('operation-field').hidden = mode.value !== 'decision';
  renderVerificationProfile();
  if (!graphContainer.hidden) graph.render(policy.value, { readOnly });
}

function localizedError(de, en) {
  return Object.assign(new Error(t(de, en)), { translations: [de, en] });
}

function inputJson(value, [de, en], format = language.value) {
  if (format === 'shacl') {
    if (!value.trim()) throw localizedError(`${de} braucht Turtle-Inhalt.`, `${en} requires Turtle content.`);
    return JSON.stringify(value);
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw localizedError(`${de} braucht gültiges JSON.`, `${en} requires valid JSON.`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw localizedError(`${de} braucht ein JSON-Objekt.`, `${en} requires a JSON object.`);
  }
  return value;
}

function verificationInputJson(text) {
  if (!savedRule?.credential || savedRule.credential.format === 'vc-data-integrity') {
    return inputJson(text, ['Der Prüfinput', 'The input']);
  }
  const value = text.trim();
  if (!value) throw localizedError('Lade ein Beispiel oder gib ein signiertes Credential ein.', 'Load an example or enter a signed credential.');
  return JSON.stringify(value);
}

function draftRuleJson() {
  const policyJson = inputJson(policy.value, ['Die Regel', 'The rule']);
  const urlFields = mode.value === 'url'
    ? `,"returnUrl":${JSON.stringify(returnUrl.value.trim())},"failUrl":${JSON.stringify(failUrl.value.trim())}`
    : '';
  const credentialField = savedRule?.credential ? `,"credential":${JSON.stringify(savedRule.credential)}` : '';
  const walletField = savedRule?.wallet ? ',"wallet":true' : '';
  const bundleField = savedRule?.bundle ? `,"bundle":${JSON.stringify(savedRule.bundle)}` : '';
  const verificationText = verification.value.trim();
  const verificationField = verificationText ? `,"verification":${inputJson(verificationText, [
    'Das Prüfprofil', 'The verification profile',
  ], 'odrl')}` : '';
  return `{"language":${JSON.stringify(language.value)},"policy":${policyJson},"responseMode":${JSON.stringify(mode.value)}${urlFields}${credentialField}${verificationField}${walletField}${bundleField}}`;
}

function verificationRequestBody() {
  const input = verificationInputJson(data.value);
  let operation = '';
  if (savedRule.responseMode === 'decision') {
    const reference = operationInput.value.trim();
    if (!operationPattern.test(reference)) {
      throw localizedError('Gib eine gültige Vorgangsreferenz ein, zum Beispiel order-1042.',
        'Enter a valid operation reference, for example order-1042.');
    }
    operation = `,"operationId":${JSON.stringify(reference)}`;
  }
  const body = `{"data":${input}${operation}}`;
  if (requestEncoder.encode(body).length > maxVerifyBody) {
    throw localizedError('Die Prüfanfrage darf höchstens 96 KiB groß sein.',
      'The verification request must be at most 96 KiB.');
  }
  return body;
}

async function request(path, options = {}) {
  const current = editorSession;
  const headers = new Headers(options.headers);
  if (bearer) headers.set('Authorization', `Bearer ${bearer}`);
  const response = await fetch(path, {
    credentials: 'same-origin',
    mode: 'same-origin',
    redirect: 'error',
    cache: 'no-store',
    signal: current?.signal,
    ...options,
    headers,
  });
  let body;
  try {
    body = await response.json();
  } catch {
    throw localizedError(
      `Der Server hat keine JSON-Antwort geliefert (HTTP ${response.status}).`,
      `The server did not return a JSON response (HTTP ${response.status}).`,
    );
  }
  if (current !== editorSession) throw new DOMException('Editor session ended', 'AbortError');
  return { response, body };
}

function serverError(response, body) {
  const detail = typeof body?.error === 'string' ? ` ${body.error}` : '';
  return localizedError(`Der Server meldet HTTP ${response.status}.${detail}`, `The server returned HTTP ${response.status}.${detail}`);
}

async function run(message, action) {
  if (busy) return;
  const current = editorSession;
  busy = true;
  refreshControls();
  report(message);
  try {
    await action();
  } catch (error) {
    if (current !== editorSession) return;
    const detail = error?.message ? ` ${error.message}` : '';
    report(error?.translations ?? [
      `Die Anfrage konnte nicht abgeschlossen werden.${detail}`,
      `The request could not be completed.${detail}`,
    ], 'error');
  } finally {
    if (current === editorSession) {
      busy = false;
      refreshControls();
    }
  }
}

function reportDraftState() {
  if (graph.hasPendingEdit()) report([
    'Übernimm oder verwirf die Änderungen an der Bedingung vor dem Speichern oder Prüfen.',
    'Apply or discard the changes to the condition before saving or verifying.',
  ]);
  else if (hasDraft()) report(['Entwurf geändert. Speichere die Regel vor der Prüfung.', 'Draft changed. Save the rule before verifying.']);
  else if (savedRule) report(activeRuleMessage);
}

function onDraftChange() {
  clearResponse();
  renderPolicyEditor();
  syncEndpointLabels();
  refreshControls();
  reportDraftState();
}

function startEndpointDraft(path, ruleLanguage, template) {
  graph.resetEdit();
  creating = true;
  unavailableEndpoint = false;
  savedRule = null;
  savedRuleEtag = null;
  conflictedEndpoint = null;
  savedVerificationText = '';
  verification.value = '';
  profile.open = false;
  operationInput.value = '';
  readOnly = false;
  examples = null;
  endpointInput.value = path;
  language.value = ruleLanguage;
  mode.value = 'boolean';
  returnUrl.value = '';
  failUrl.value = '';
  savedPolicyText = policyText({ language: ruleLanguage, policy: template.policy });
  policy.value = savedPolicyText;
  defaultInputText = builderInput ? '' : template.data;
  data.value = defaultInputText;
  raw.open = ruleLanguage === 'shacl';
  syncEndpoints();
  renderInputProfile();
  onDraftChange();
}

function startNestedDraft() {
  const path = '/verify/odrl-graph';
  startEndpointDraft(endpoints.includes(path) ? '/verify/' : path, 'odrl', nestedTemplate);
}

language.addEventListener('change', () => {
  raw.open = language.value === 'shacl';
  onDraftChange();
});
get('handoff-discard').addEventListener('click', () => {
  discardBuilderInput();
  refreshControls();
});
mode.addEventListener('change', onDraftChange);
policy.addEventListener('input', onDraftChange);
verification.addEventListener('input', onDraftChange);
operationInput.addEventListener('input', () => {
  if (walletRecoveryFinished) {
    data.value = '{"action":"start"}';
    report(activeRuleMessage);
  }
  clearResponse();
  refreshControls();
});
returnUrl.addEventListener('input', onDraftChange);
failUrl.addEventListener('input', onDraftChange);
endpointInput.addEventListener('input', onDraftChange);
data.addEventListener('input', () => {
  clearResponse();
  refreshControls();
  if (savedRule && !conflictedEndpoint && !hasDraft()) {
    report(['Prüfinput geändert. Die Regel ist weiterhin aktiv.', 'Input changed. The saved rule is still active.']);
  }
});

for (const [button, sample] of [[validExample, 'valid'], [tamperedExample, 'tampered']]) {
  button.addEventListener('click', () => {
    if (!examples || busy) return;
    data.value = examples[sample];
    clearResponse();
    report(sample === 'valid'
      ? ['Signiertes Original geladen. Starte die Prüfung am Server.', 'Signed original loaded. Start the server verification.']
      : ['Manipulierter Fall geladen. Starte die Prüfung am Server.', 'Tampered case loaded. Start the server verification.']);
  });
}

endpointPicker.addEventListener('change', () => {
  const selection = endpointPicker.value;
  if (!selection) return;
  if (!unavailableEndpoint && (hasDraft() || data.value !== defaultInputText) && !window.confirm(t(
    'Geänderten Entwurf oder Prüfinput verwerfen und Endpunkt wechseln?',
    'Discard the edited draft or verification input and switch endpoints?',
  ))) {
    syncEndpoints();
    return;
  }
  clearResponse();
  if (selection === '__new__') {
    const path = newEndpointPath();
    if (!path) { syncEndpoints(); return; }
    startEndpointDraft(path, language.value, templates[language.value]);
    endpointInput.focus();
    return;
  }
  void run(['Regel für den Endpunkt wird geladen …', 'Loading the rule for this endpoint …'], async () => {
    try {
      await loadSavedEndpoint(selection);
      selectEndpointInUrl(selection);
    } finally {
      syncEndpoints();
    }
  });
});

async function loadSavedEndpoint(endpoint) {
  const { response, body } = await request(`/admin/rule?endpoint=${encodeURIComponent(endpoint)}`);
  if (!response.ok) throw serverError(response, body);
  csrfToken = body.csrfToken;
  applySavedRule(body, response.headers.get('ETag'));
  showActiveRule(true, activeRuleMessage);
}

loadTemplate.addEventListener('click', () => {
  const template = templates[language.value];
  const replacement = policyText({ language: language.value, policy: template.policy });
  const replacesRuleEdit = policy.value !== savedPolicyText && policy.value !== replacement;
  const replacesInputEdit = data.value !== defaultInputText && data.value !== template.data;
  if ((graph.hasPendingEdit() || replacesRuleEdit || replacesInputEdit) && !window.confirm(t(
    'Geänderten Entwurf oder Prüfinput durch die Vorlage ersetzen?',
    'Replace the edited draft or verification input with the template?',
  ))) return;
  graph.resetEdit();
  policy.value = replacement;
  defaultInputText = template.data;
  data.value = defaultInputText;
  onDraftChange();
});

loadNestedTemplate.addEventListener('click', () => {
  if (busy || readOnly || !allEndpoints()) return;
  if ((hasDraft() || data.value !== defaultInputText) && !window.confirm(t(
    'Aktuellen Entwurf und Prüfinput durch das Beispiel ersetzen?',
    'Replace the current draft and verification input with the example?',
  ))) return;
  startNestedDraft();
});

testRule.addEventListener('click', () => {
  if (busy || unavailableEndpoint || !csrfToken || graph.hasPendingEdit()
      || builderInput || savedRule?.bundle || savedRule?.wallet) return;
  const hasDocumentProfile = Boolean(savedVerificationText || verification.value.trim());
  tester.open({
    input: data.value,
    format: savedRule?.credential?.format ?? (language.value === 'shacl' ? 'turtle' : 'json'),
    manual: hasDocumentProfile,
    examples,
    async test(text, signal) {
      if (hasDocumentProfile && verification.value.trim() !== savedVerificationText) {
        throw localizedError('Speichere zuerst das geänderte Prüfprofil für diesen Endpunkt.',
          'Save the changed verification profile for this endpoint first.');
      }
      const rule = draftRuleJson();
      const input = verificationInputJson(text);
      if (requestEncoder.encode(rule).length > maxVerifyBody
          || requestEncoder.encode(`{"data":${input}}`).length > maxVerifyBody) {
        throw localizedError('Regel und Prüfeingabe dürfen jeweils höchstens 96 KiB groß sein.',
          'The rule and test input must each be at most 96 KiB.');
      }
      const endpoint = creating ? endpointInput.value.trim() : activeEndpoint;
      const testPath = principal?.enabled ? `/admin/test-rule?endpoint=${encodeURIComponent(endpoint)}` : '/admin/test-rule';
      const { response, body } = await request(testPath, {
        method: 'POST',
        signal,
        headers: { 'Content-Type': 'application/json', 'X-ProofSieve-Token': csrfToken },
        body: `{"rule":${rule},"data":${input}}`,
      });
      if (!response.ok) throw serverError(response, body);
      return body;
    },
  });
});

save.addEventListener('click', () => {
  if (unavailableEndpoint || !csrfToken || readOnly || conflictedEndpoint || graph.hasPendingEdit()) return;
  clearResponse();
  void run(['Regel wird gespeichert …', 'Saving rule …'], async () => {
    const endpoint = creating ? endpointInput.value.trim() : activeEndpoint;
    if (creating && endpoints.includes(endpoint)) {
      throw localizedError('Dieser Endpunkt existiert. Wähle ihn zum Bearbeiten aus.', 'This endpoint already exists. Select it to edit it.');
    }
    if (!endpoint) throw localizedError('Gib einen Endpunktpfad an.', 'Enter an endpoint path.');
    if (!creating && !savedRuleEtag) {
      throw localizedError('Die Regelversion fehlt. Lade die Seite neu.', 'The rule version is missing. Reload the page.');
    }
    const { response, body } = await request(`/admin/rule?endpoint=${encodeURIComponent(endpoint)}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-ProofSieve-Token': csrfToken,
        ...(creating ? { 'If-None-Match': '*' } : { 'If-Match': savedRuleEtag }),
      },
      body: draftRuleJson(),
    });
    if (response.status === 412) {
      conflictedEndpoint = endpoint;
      throw localizedError('Die Regel wurde zwischenzeitlich gespeichert. Dein Entwurf ist noch sichtbar. Lade die aktuelle Regel, um weiterzuarbeiten.',
        'The rule was saved in the meantime. Your draft is still visible. Load the current rule to continue.');
    }
    if (!response.ok) throw serverError(response, body);
    if (creating) selectEndpointInUrl(body.endpoint);
    applySavedRule(body, response.headers.get('ETag'));
    showActiveRule(false, ['Regel gespeichert und am Server aktiv.', 'Rule saved and active on the server.'], 'success');
  });
});

reloadRule.addEventListener('click', () => {
  const endpoint = conflictedEndpoint;
  if (!endpoint || !window.confirm(t('Aktuelle Regel laden und Entwurf und Prüfinput ersetzen?',
    'Load the current rule and replace the draft and verification input?'))) return;
  void run(['Aktuelle Regel wird geladen …', 'Loading the current rule …'], () => loadSavedEndpoint(endpoint));
});

verify.addEventListener('click', () => {
  if (unavailableEndpoint || !csrfToken || hasDraft() || builderInput || conflictedEndpoint || walletRecoveryFinished) return;
  clearResponse();
  void run(['Eingabe wird am Server geprüft …', 'Verifying input on the server …'], async () => {
    const requestBody = verificationRequestBody();
    const { response, body } = await request(activeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(!savedRule.wallet && savedRuleEtag ? { 'If-Match': savedRuleEtag } : {}),
      },
      body: requestBody,
    });
    httpStatus.textContent = `HTTP ${response.status}`;
    if (response.status === 412 && body?.code === 'rule_version_conflict') {
      conflictedEndpoint = activeEndpoint;
      throw localizedError('Die gespeicherte Regel wurde geändert. Lade die aktuelle Regel, bevor du erneut prüfst.',
        'The saved rule has changed. Load the current rule before verifying again.');
    }
    const walletFeedback = savedRule.wallet ? walletMessage(response.status, body) : null;
    if (savedRule.wallet && (response.status === 201 || response.status === 202)) {
      const reference = operationInput.value.trim();
      const completion = response.status === 201 ? walletCompletionInput(body, reference) : null;
      if (body?.state !== 'pending' || body.operationId !== reference || (response.status === 201 && !completion)) {
        throw serverError(response, body);
      }
      hasResult = true;
      output.textContent = formatJson(body);
      walletDeadline.update(activeEndpoint, requestBody, response.status, body);
      if (completion) data.value = formatJson(completion);
      report(walletFeedback);
      return;
    }
    if (savedRule.wallet && walletFeedback && [409, 429, 503].includes(response.status) && !body?.decisionId) {
      hasResult = true;
      output.textContent = formatJson(body);
      walletRecoveryFinished = response.status === 409;
      walletDeadline.update(activeEndpoint, requestBody, response.status, body);
      report(walletFeedback, 'error');
      return;
    }
    if (savedRule.responseMode === 'decision') {
      const outcomes = {
        allow: ['Freigabe für diesen Vorgang erteilt.', 'This operation is approved.'],
        deny: ['Vorgang abgelehnt.', 'This operation is denied.'],
        indeterminate: ['Die Prüfung blieb unbestimmt. Der Vorgang bleibt gesperrt.',
          'Verification is inconclusive. The operation remains blocked.'],
      };
      const deliveries = {
        delivered: [200, ['Vorgang freigegeben und weitergeleitet.', 'The operation was approved and forwarded.']],
        rejected: [502, ['Der Zieldienst meldet einen Fehler.', 'The destination reported a failure.']],
        unknown: [503, ['Die Zustellung konnte nicht bestätigt werden.', 'Delivery could not be confirmed.']],
        pending: [503, ['Die Zustellung ist noch offen.', 'Delivery is still pending.']],
        not_forwarded: [body?.outcome === 'deny' ? 403 : 503, outcomes[body?.outcome]],
      };
      const delivery = body?.delivery ? deliveries[body.delivery.state] : null;
      const denialStatus = savedRule.wallet && body?.outcome === 'deny' ? 403 : 200;
      const expectedStatus = delivery?.[0] ?? (body?.outcome === 'indeterminate' ? 503 : denialStatus);
      if (!Object.hasOwn(outcomes, body?.outcome) || typeof body.decisionId !== 'string'
          || body.operationId !== operationInput.value.trim() || body.valid !== (body.outcome === 'allow')
          || (body.delivery && !delivery?.[1]) || response.status !== expectedStatus) {
        throw serverError(response, body);
      }
      hasResult = true;
      output.textContent = formatJson(body);
      walletRecoveryFinished = savedRule.wallet === true && response.status === 503
        && body.outcome === 'indeterminate' && body.reason === 'wallet_evidence_interrupted';
      evidence.offer(principal?.id, activeEndpoint, operationInput.value.trim(), body);
      if (savedRule.credential) {
        credentialResult = body.reason === 'credential_rejected' ? 'credential' : body.valid ? 'allowed' : 'policy';
        renderCredentialFlow();
      }
      report(delivery?.[1] ?? walletFeedback ?? outcomes[body.outcome], response.ok && body.valid ? 'success' : 'info');
      return;
    }
    if (savedRule.credential && response.status === 403 && body?.stage === 'credential') {
      hasResult = true;
      output.textContent = formatJson(body);
      credentialResult = 'credential';
      renderCredentialFlow();
      report(['Credential-Prüfung fehlgeschlagen. Die ODRL-Regel wurde nicht ausgeführt.', 'Credential verification failed. The ODRL rule was skipped.'], 'error');
      return;
    }
    if (!response.ok && !(response.status === 403 && body === false)) {
      throw serverError(response, body);
    }
    const valid = typeof body === 'boolean' ? body : body?.valid;
    if (typeof valid !== 'boolean') {
      throw localizedError('Der Server hat kein gültiges Prüfergebnis geliefert.', 'The server did not return a valid verification result.');
    }
    hasResult = true;
    output.textContent = formatJson(body);
    const target = typeof body?.redirectUrl === 'string' ? new URL(body.redirectUrl) : null;
    if (target?.protocol === 'https:') {
      resultLink.href = target.href;
      resultLink.hidden = false;
    }
    if (savedRule.credential) {
      credentialResult = valid ? 'allowed' : 'policy';
      renderCredentialFlow();
      report(valid
        ? ['Aussteller-Nachweis geprüft. Die ODRL-Regel gibt den Input frei.', 'Issuer proof verified. The ODRL rule allows the input.']
        : ['Aussteller-Nachweis geprüft. Die ODRL-Regel lehnt den Input ab.', 'Issuer proof verified. The ODRL rule refuses the input.'],
      valid ? 'success' : 'info');
      return;
    }
    report(valid
      ? ['Die gespeicherte Regel gibt den Input frei.', 'The saved rule allows the input.']
      : ['Die gespeicherte Regel lehnt den Input ab.', 'The saved rule refuses the input.'],
    valid ? 'success' : 'info');
  });
});

function renderLanguage() {
  const placeholder = endpointPicker.querySelector('option[value=""]');
  if (placeholder) placeholder.textContent = t(...selectEndpointText);
  const createOption = endpointPicker.querySelector('option[value="__new__"]');
  if (createOption) createOption.textContent = t(...createEndpointText);
  status.textContent = t(...statusMessage);
  syncEndpointLabels();
  renderPolicyEditor();
  renderInputProfile();
  renderHandoffMessage();
  renderEmptyResponse();
}

onLanguageChange(renderLanguage);
renderLanguage();

function clearEditor() {
  editorSession?.abort();
  editorSession = null;
  evidence.setAvailable(false);
  walletDeadline.reset();
  bearer = null;
  principal = null;
  csrfToken = '';
  savedRule = null;
  savedRuleEtag = null;
  savedPolicyText = '';
  defaultInputText = '';
  savedVerificationText = '';
  capabilities = {};
  examples = null;
  busy = false;
  editor.hidden = true;
  openapi.hidden = true;
  if (get('tester').open) get('tester').close();
  policy.value = '';
  data.value = '';
  verification.value = '';
  profile.open = false;
  operationInput.value = '';
  returnUrl.value = '';
  failUrl.value = '';
  endpointInput.value = '';
  endpoints = [];
  creating = false;
  unavailableEndpoint = false;
  conflictedEndpoint = null;
  syncEndpoints();
  graph.render('');
  clearResponse();
  handoff.hidden = true;
}

function startEditor(access) {
  principal = access.principal;
  bearer = access.token;
  editorSession = new AbortController();
  editor.hidden = false;
  if (access.token) get('editor-heading').focus();
  openapi.hidden = false;
  void run(['Gespeicherte Regel wird geladen …', 'Loading saved rule …'], loadInitialRule);
  if (bearer) {
    void request('/openapi.json').then(({ response, body }) => {
      evidence.setAvailable(response.ok && hasEvidenceExport(body));
    }).catch(() => {});
  }
}

function selectEndpointInUrl(endpoint) {
  initialQuery.set('endpoint', endpoint);
  initialQuery.delete('case');
  initialQuery.delete('example');
  history.replaceState(history.state, '', `${location.pathname}?${initialQuery}${location.hash}`);
}

function showUnavailableEndpoint(available, editorToken) {
  endpoints = available;
  csrfToken = editorToken;
  unavailableEndpoint = true;
  syncEndpoints();
  report(unavailableEndpointText, 'error');
}

async function loadInitialRule() {
  const requested = initialQuery.get('endpoint');
  if (requested !== null && principal?.enabled && !principal.endpoints.includes(requested)) {
    showUnavailableEndpoint(principal.endpoints, principal.csrfToken);
    return;
  }
  const endpoint = requested ?? (allEndpoints() ? null : principal.endpoints[0]);
  if (!endpoint && requested === null && !allEndpoints()) {
    csrfToken = principal.csrfToken;
    endpoints = principal.endpoints;
    startEndpointDraft(newEndpointPath(), 'odrl', templates.odrl);
    return;
  }
  const adminPath = endpoint == null ? '/admin/rule' : `/admin/rule?endpoint=${encodeURIComponent(endpoint)}`;
  const { response, body } = await request(adminPath);
  if (requested !== null && [400, 403, 404].includes(response.status)) {
    if (principal?.enabled) {
      showUnavailableEndpoint(principal.endpoints.filter(path => path !== requested), principal.csrfToken);
    } else {
      const available = await request('/admin/rule');
      if (!available.response.ok) throw serverError(available.response, available.body);
      showUnavailableEndpoint(available.body.endpoints, available.body.csrfToken);
    }
    return;
  }
  if (!response.ok) throw serverError(response, body);
  if (typeof body?.csrfToken !== 'string' || !body.csrfToken) {
    throw localizedError('Der Server hat keinen Sitzungsschlüssel geliefert. Lade die Seite neu.', 'The server did not return a session token. Reload the page.');
  }
  if (body.rule) {
    applySavedRule(body, response.headers.get('ETag'));
    if (!endpoint && allEndpoints() && initialQuery.get('example') === 'nested') {
      startNestedDraft();
    } else {
      showActiveRule(true, activeRuleMessage, 'info', initialQuery.get('case') === 'tampered' ? 'tampered' : 'valid');
    }
  } else {
    const template = templates[language.value];
    policy.value = policyText({ language: language.value, policy: template.policy });
    defaultInputText = template.data;
    data.value = defaultInputText;
    renderPolicyEditor();
    report(['Vorlage geladen. Speichere sie, um die erste Regel zu aktivieren.', 'Template loaded. Save it to activate the first rule.']);
  }
  csrfToken = body.csrfToken;
}

openapi.hidden = true;
openapi.addEventListener('click', event => {
  if (!principal?.enabled) return;
  event.preventDefault();
  void run(['OpenAPI wird geladen …', 'Loading OpenAPI …'], async () => {
    const { response, body } = await request('/openapi.json');
    if (!response.ok) throw serverError(response, body);
    const url = URL.createObjectURL(new Blob([formatJson(body)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'proofsieve-openapi.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    report(['OpenAPI für deine Endpunkte heruntergeladen.', 'Downloaded OpenAPI for your endpoints.']);
  });
});

void createAccess(get('access'), {
  onAccess: startEditor,
  onLogout: clearEditor,
  requestedEndpoint: () => initialQuery.get('endpoint'),
  requestedExampleCase: () => initialQuery.get('case'),
  selectEndpointInUrl,
  readHandoff: () => builderInput,
  discardHandoff: discardBuilderInput,
}).start();
