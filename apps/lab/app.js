import { t, onLanguageChange } from '../shared/i18n.js';
import { exampleIds, examples, checkLabels, fieldLabels, formatLabels, caseLabels, caseReasonsDe } from './presentation.js';
import { evaluate, responsePreview } from './model.js';

const $ = id => document.getElementById(id);
const storagePrefix = 'proofsieve-draft-v1:';
const resultLabels = { pass: ['Freigegeben', 'Approved'], fail: ['Abgelehnt', 'Denied'], skip: ['Nicht entscheidbar', 'Indeterminate'] };
const stepLabels = { pass: ['Erfüllt', 'Met'], fail: ['Nicht erfüllt', 'Unmet'], skip: ['Nicht belegt', 'Unproven'] };
const outputModes = {
  boolean: ['Boolesche Antwort', 'Boolean response'],
  link: ['Weiterleitungslink', 'Continuation link'],
  forward: ['Serverseitige Weiterleitung', 'Server-side forwarding'],
};
const comparisonLabels = { eq: ['ist gleich', 'equals'], gteq: ['mindestens', 'at least'], lteq: ['höchstens', 'at most'] };
const defaults = {
  boolean: { mode: 'boolean' },
  link: { mode: 'link', targetTemplate: 'https://demo.example/continue/{continuation}' },
  forward: { mode: 'forward', destination: 'https://demo.example/accepted', payload: 'approved-request-body' }
};
const source = new Map();
const drafts = new Map();
let rule;
let testCase;
let statusMessage;
let loadError;

function element(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if ((key === 'className' || key === 'value') && value != null) node[key] = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) node.setAttribute(key, value === true ? '' : value);
  }
  node.append(...children.flat().filter(child => child != null));
  return node;
}

const text = (tag, value, className) => element(tag, { className }, value);
const button = (label, action, className = 'button') =>
  element('button', { type: 'button', className, onclick: action }, label);
const badge = (label, state = 'info') => element('span', { className: 'badge', 'data-state': state }, label);
const hint = value => text('p', value, 'hint');
const heading = (title, action) => element('div', { className: 'subhead' }, text('h3', title), action);
const json = value => text('pre', JSON.stringify(value, null, 2), 'json-preview');
const labelize = key => key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replaceAll('-', ' ').replace(/^./, char => char.toUpperCase());
const localLabel = (labels, key, fallback = labelize(key ?? '')) => Object.hasOwn(labels, key) ? t(...labels[key]) : fallback;
const friendly = key => t(fieldLabels[key] ?? labelize(key), labelize(key));
const checkName = check => localLabel(checkLabels, check.id);
const caseName = scenario => localLabel(caseLabels, scenario.id);
const display = value => value === undefined ? '–' : value === true ? t('Ja', 'Yes') : value === false ? t('Nein', 'No') : String(value);

function select(options, value) {
  const input = element('select', {}, Object.entries(options).map(([key, label]) =>
    element('option', { value: key }, t(...label))));
  input.value = value;
  return input;
}

function field(label, input) {
  return element('label', { className: 'field' }, text('span', label), input);
}

function setStatus(de, en) {
  statusMessage = [de, en];
  $('app-status').textContent = t(...statusMessage);
}

function saveDraft() {
  try {
    localStorage.setItem(storagePrefix + rule.id, JSON.stringify(rule));
    setStatus('Entwurf im Browser gespeichert', 'Draft saved in this browser');
  } catch {
    setStatus('Entwurf im Arbeitsspeicher · Export verfügbar', 'Draft held in memory · export available');
  }
}

function loadDraft(id) {
  if (drafts.has(id)) return drafts.get(id);
  let draft;
  try {
    const saved = JSON.parse(localStorage.getItem(storagePrefix + id));
    if (saved?.id === id && Array.isArray(saved.checks) && saved.odrl?.permission?.[0]?.constraint && saved.output && saved.appliesTo) {
      draft = { ...saved, cases: source.get(id).cases, sources: source.get(id).sources };
    }
  } catch {
    // Fall back to the shipped rule if browser storage is unavailable.
  }
  draft ??= structuredClone(source.get(id));
  drafts.set(id, draft);
  return draft;
}

function showRule(id) {
  rule = loadDraft(id);
  testCase = rule.cases[0];
  history.replaceState(null, '', `#${id}`);
  setStatus('Testumgebung · synthetische Prüfdaten', 'Sandbox · synthetic verification data');
  render();
  $('export-rule').disabled = false;
  $('reset-rule').disabled = false;
}

function openDialog(title, body) {
  $('dialog-title').textContent = title;
  $('dialog-body').replaceChildren(body);
  if (!$('dialog').open) $('dialog').showModal();
}

function editDialog(title, controls, commit) {
  const error = element('p', { className: 'hint', role: 'alert' });
  const form = element('form', {
    className: 'field-list',
    onsubmit: event => {
      event.preventDefault();
      try {
        commit();
      } catch (exception) {
        error.textContent = exception.message;
        return;
      }
      saveDraft();
      $('dialog').close();
      render();
      $('config-heading').focus({ preventScroll: true });
    }
  }, controls, error, element('div', { className: 'input-row' },
    button(t('Abbrechen', 'Cancel'), () => $('dialog').close()),
    element('button', { className: 'button primary', type: 'submit' }, t('Übernehmen', 'Apply'))));
  openDialog(title, form);
}

function configField(key, value) {
  let input, read;
  if (typeof value === 'boolean') {
    input = select({ true: ['Ja', 'Yes'], false: ['Nein', 'No'] }, String(value));
    read = () => input.value === 'true';
  } else if (typeof value === 'number') {
    input = element('input', { type: 'number', step: 'any', required: true, value });
    read = () => input.valueAsNumber;
  } else if (Array.isArray(value) && value.every(item => typeof item === 'string')) {
    input = element('textarea', { rows: Math.min(Math.max(value.length, 2), 6), placeholder: t('Eine Angabe je Zeile', 'One entry per line') });
    input.value = value.join('\n');
    read = () => input.value.split('\n').map(line => line.trim()).filter(Boolean);
  } else if (value && typeof value === 'object') {
    input = element('textarea', { rows: Math.min(JSON.stringify(value, null, 2).split('\n').length, 6) });
    input.value = JSON.stringify(value, null, 2);
    read = () => {
      let parsed;
      try { parsed = JSON.parse(input.value); }
      catch { throw new Error(t(`„${friendly(key)}“ muss gültiges JSON enthalten.`, `${friendly(key)} must contain valid JSON.`)); }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) !== Array.isArray(value)) {
        throw new Error(t(`„${friendly(key)}“ muss ein ${Array.isArray(value) ? 'Array' : 'Objekt'} bleiben.`,
          `${friendly(key)} must remain an ${Array.isArray(value) ? 'array' : 'object'}.`));
      }
      return parsed;
    };
  } else {
    input = element('input', { type: 'text', value: value ?? '' });
    read = () => input.value.trim();
  }
  return { key, control: field(friendly(key), input), read };
}

function editObject(title, object, onSave) {
  const fields = Object.entries(object).map(([key, value]) => configField(key, value));
  editDialog(title, fields.map(item => item.control), () => onSave(Object.fromEntries(fields.map(item => [item.key, item.read()]))));
}

function editSigner(signer, check) {
  const name = element('input', { required: true, value: signer.displayName });
  const identity = element('input', { required: true, value: signer.id });
  const method = select({ 'local-x509': ['Lokal · X.509', 'Local · X.509'], external: ['Externer Prüfdienst', 'External verifier'] }, signer.method);
  const profile = element('input', { value: signer.trustProfile ?? '' });
  const endpoint = element('input', { type: 'url', value: signer.connector?.endpoint ?? '', placeholder: 'https://verifier.example/check' });
  const profileField = field(t('Vertrauensprofil', 'Trust profile'), profile);
  const endpointField = field(t('Prüfdienst-URL', 'Verifier URL'), endpoint);
  const toggle = () => {
    profileField.hidden = method.value === 'external';
    profile.disabled = profileField.hidden;
    profile.required = !profileField.hidden;
    endpointField.hidden = !profileField.hidden;
    endpoint.disabled = endpointField.hidden;
    endpoint.required = !endpointField.hidden;
  };
  toggle();
  method.addEventListener('change', toggle);
  editDialog(t(`Signierer bearbeiten · ${signer.displayName}`, `Edit signer · ${signer.displayName}`), [
    field(t('Anzeigename', 'Display name'), name), field(t('Erwartete Signierer-ID', 'Expected signer ID'), identity), field(t('Prüfweg', 'Verification method'), method), profileField, endpointField,
    hint(t('Der Prüfnachweis muss die erwartete Identität und die Signatur für denselben Auftrag belegen.', 'The evidence must establish the expected identity and the signature for the same request.'))
  ], () => {
    const id = identity.value.trim();
    if (!id || check.configuration.signers.some(item => item !== signer && item.id.trim() === id)) {
      throw new Error(t('Jeder Signierer braucht eine eigene, eindeutige ID.', 'Each signer needs a unique ID.'));
    }
    const edited = { id, displayName: name.value.trim(), method: method.value };
    if (method.value === 'external') {
      const url = new URL(endpoint.value);
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error(t('Bitte eine HTTPS-Adresse ohne Zugangsdaten angeben.', 'Enter an HTTPS URL without credentials.'));
      edited.connector = {
        authentication: 'configured-service-identity',
        requireResponseFields: ['verifiedSignerId', 'artifactDigest', 'signatureValid'],
        bindToRequest: true,
        ...signer.connector,
        endpoint: endpoint.value.trim()
      };
    } else {
      edited.trustProfile = profile.value.trim();
    }
    check.configuration.signers[check.configuration.signers.indexOf(signer)] = edited;
  });
}

function editCheck(check) {
  if (check.kind === 'distinct-signatures') {
    openDialog(checkName(check), element('div', { className: 'check-list' },
      check.configuration.signers.map(signer => signerRow(signer, check)),
      hint(t('Signierer-IDs werden pro Auftrag nur einmal gezählt.', 'Each signer ID counts once per request.'))));
    return;
  }
  editObject(checkName(check), check.configuration, updated => { check.configuration = updated; });
}

function signerRow(signer, check) {
  const method = signer.method === 'external' ? signer.connector.endpoint : signer.trustProfile;
  return button(
    element('span', {}, text('strong', signer.displayName, 'check-name'), text('small', method, 'hint')),
    () => editSigner(signer, check), 'check-row'
  );
}

function constraintRow(constraint, check) {
  const threshold = check.kind === 'distinct-signatures';
  const operators = threshold
    ? { gteq: comparisonLabels.gteq }
    : typeof constraint.rightOperand === 'number' ? comparisonLabels : { eq: comparisonLabels.eq };
  const op = select(operators, constraint.operator);
  const expected = configField('expectedValue', constraint.rightOperand);
  expected.control.firstElementChild.textContent = t('Sollwert', 'Expected value');
  const expectedInput = expected.control.lastElementChild;
  if (threshold) {
    expectedInput.min = 1;
    expectedInput.max = check.configuration.signers.length;
    expectedInput.step = 1;
  }
  op.addEventListener('change', () => {
    constraint.operator = op.value;
    saveDraft();
    renderRun();
  });
  expectedInput.addEventListener('change', () => {
    if (!expectedInput.checkValidity()) {
      expectedInput.reportValidity();
      expectedInput.value = constraint.rightOperand;
      return;
    }
    constraint.rightOperand = expected.read();
    saveDraft();
    renderRun();
  });
  return element('div', { className: 'field-list condition' },
    text('strong', threshold ? t('Freigabeschwelle', 'Approval threshold') : checkName(check), 'check-name'),
    element('div', { className: 'input-row' }, field(t('Vergleich', 'Comparison'), op), expected.control),
    threshold ? hint(t(`Zugelassen sind ${check.configuration.signers.length} unterschiedliche Signierer.`,
      `${check.configuration.signers.length} distinct signers are approved.`)) : null);
}

function graphJoin(count) {
  const namespace = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(namespace, 'svg');
  svg.setAttribute('class', 'graph-join');
  svg.setAttribute('viewBox', '0 0 100 22');
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('aria-hidden', 'true');
  const wire = document.createElementNS(namespace, 'path');
  const branches = Array.from({ length: count }, (_, index) => `M${(index + 0.5) * 100 / count} 0V8H50`);
  wire.setAttribute('d', [...branches, 'M50 8V22'].join(' '));
  wire.setAttribute('vector-effect', 'non-scaling-stroke');
  svg.append(wire);
  return svg;
}

function renderConfig() {
  const conditions = rule.odrl.permission[0].constraint;
  const signerCheck = rule.checks.find(check => check.kind === 'distinct-signatures');
  const mode = select(outputModes, rule.output.mode);
  mode.addEventListener('change', () => {
    rule.output = structuredClone(defaults[mode.value]);
    saveDraft();
    renderConfig();
    renderRun();
    $('config-panel').querySelector('[data-output-mode]')?.focus();
  });
  mode.setAttribute('data-output-mode', '');
  const outputFields = Object.entries(rule.output).filter(([key]) => key !== 'mode').map(([key, value]) => {
    const item = configField(key, value);
    item.control.classList.add('field--wide');
    item.control.lastElementChild.addEventListener('change', () => {
      rule.output[key] = item.read();
      saveDraft();
      renderRun();
    });
    return item.control;
  });
  $('config-panel').replaceChildren(
    heading(t('Eingang', 'Input'), button(t('Bearbeiten', 'Edit'), () => editObject(t('Eingangsvariante', 'Input variant'), rule.appliesTo, updated => { rule.appliesTo = updated; }))),
    element('div', { className: 'field-list' },
      ...Object.entries(rule.appliesTo).map(([key, value]) => element('div', { className: 'field' },
        text('span', friendly(key), 'hint'), text('strong', key === 'format' ? localLabel(formatLabels, value, value) : display(value))))),
    heading(signerCheck ? t('Zugelassene Signierer', 'Approved signers') : t('Prüfbausteine', 'Verification checks')),
    element('div', { className: 'check-list' }, signerCheck
      ? signerCheck.configuration.signers.map(signer => signerRow(signer, signerCheck))
      : rule.checks.map(check => button(
        element('span', {}, text('strong', checkName(check), 'check-name'), text('small', t('Prüfparameter öffnen', 'Open check settings'), 'hint')),
        () => editCheck(check), 'check-row'))),
    heading(t('Freigabebedingungen', 'Approval conditions'), badge(t('UND', 'AND'))),
    ...conditions.map(condition => constraintRow(condition, rule.checks.find(check => check.fact === condition.leftOperand))),
    heading(t('Ausgang bei Freigabe', 'Response on approval')),
    element('div', { className: 'field-list' }, field(t('Rückgabe', 'Response'), mode), outputFields)
  );
}

function renderGraph(result) {
  const signerCheck = rule.checks.find(check => check.kind === 'distinct-signatures');
  const sources = signerCheck
    ? signerCheck.configuration.signers.map(signer => {
      const results = testCase.simulatedSignerResults?.filter(item => item.signerId === signer.id) ?? [];
      const confirmed = results.some(item => item.result === 'valid' && item.sameArtifact);
      const state = confirmed ? 'pass' : results.some(item => item.result !== 'missing') ? 'fail' : 'skip';
      return button(element('span', {}, text('strong', signer.displayName),
        text('small', signer.method === 'external' ? t('Prüfdienst', 'Verifier service') : t('X.509 lokal', 'Local X.509'), 'hint'), badge(t(...stepLabels[state]), state)),
      () => editSigner(signer, signerCheck), 'graph-node');
    })
    : rule.checks.map(check => {
      const checks = result.trace.filter(step => step.leftOperand === check.fact);
      const state = checks.find(step => step.state === 'fail')?.state ?? checks.find(step => step.state === 'skip')?.state ?? 'pass';
      return button(element('span', {}, text('strong', checkName(check)), badge(t(...stepLabels[state]), state)),
        () => editCheck(check), 'graph-node');
    });
  const decision = t(...resultLabels[result.state]);
  const matchedCount = result.trace.filter(step => step.state === 'pass').length;
  const conditionCount = result.trace.length;
  $('graph-panel').replaceChildren(
    heading(t('Geprüfte Eingänge', 'Verified inputs'), button('ODRL JSON-LD', () => openDialog('ODRL JSON-LD', json(rule.odrl)))),
    element('div', { className: 'graph-sources', style: `--source-count: ${sources.length}` }, sources),
    graphJoin(sources.length),
    element('div', { className: 'graph-node' },
      text('strong', signerCheck ? t('Gültige zugelassene Signierer zählen', 'Count valid approved signers') : t('Bedingungen gemeinsam auswerten', 'Evaluate all conditions together')),
      signerCheck ? text('small', t(
        `${display(result.facts[signerCheck.fact])} geprüft · ${display(result.trace[0].rightOperand)} erwartet`,
        `${display(result.facts[signerCheck.fact])} verified · ${display(result.trace[0].rightOperand)} expected`
      ), 'hint')
        : text('small', t(`${matchedCount} von ${conditionCount} Bedingungen erfüllt`,
          `${matchedCount} of ${conditionCount} conditions met`), 'hint')),
    element('div', { className: 'graph-arrow', 'aria-hidden': 'true' }, '↓'),
    element('div', { className: 'graph-node' }, text('strong', t('ODRL-Erlaubnis · uv:approve', 'ODRL permission · uv:approve')), badge(decision, result.state)),
    element('div', { className: 'graph-arrow', 'aria-hidden': 'true' }, '↓'),
    element('div', { className: 'graph-branch' },
      element('div', { className: 'graph-node' }, text('strong', t('Bei Freigabe', 'On approval')), text('small', localLabel(outputModes, rule.output.mode), 'hint')),
      element('div', { className: 'graph-node' }, text('strong', t('Sonst', 'Otherwise')), text('small', t('Keine Weiterleitung', 'No forwarding'), 'hint'))),
    hint(t('Ein Klick auf einen Eingang öffnet dieselbe Konfiguration wie in der Schnellansicht.', 'Select an input to open its settings.'))
  );
}

function localizeError(message) {
  const english = message
    .replace('Jeder Signierer braucht eine eigene, eindeutige ID.', 'Each signer needs a unique ID.')
    .replace(' braucht eine gültige HTTPS-Adresse für den Prüfdienst.', ' needs a valid HTTPS verifier URL.')
    .replace(' braucht ein Vertrauensprofil.', ' needs a trust profile.')
    .replace('Die Zielvorlage muss eine HTTPS-Adresse mit {continuation} sein.',
      'The URL template must be an HTTPS URL containing {continuation}.')
    .replace('Für die Weiterleitung fehlen eine gültige HTTPS-Adresse oder die Nutzdaten.',
      'Forwarding requires a valid HTTPS URL and payload.');
  return t(message, english);
}

function renderRun() {
  const result = evaluate(rule, testCase);
  const preview = responsePreview(rule, testCase, result);
  const original = source.get(rule.id);
  const edited = ['appliesTo', 'checks', 'odrl', 'output'].some(field =>
    JSON.stringify(rule[field]) !== JSON.stringify(original[field]));
  const met = result.trace.filter(step => step.state === 'pass').length;
  const total = result.trace.length;
  const reason = edited
    ? t(`Der aktuelle Entwurf erfüllt ${met} von ${total} Bedingungen.`, `The current draft meets ${met} of ${total} conditions.`)
    : t(caseReasonsDe[rule.id]?.[testCase.id] ?? testCase.reason, testCase.reason);
  renderGraph(result);
  $('cases-panel').replaceChildren(
    element('div', { className: 'case-list' }, rule.cases.map(scenario => {
      const control = button(element('span', {}, text('strong', caseName(scenario)),
        text('small', scenario.expected.valid ? t('Vorlage · Freigabe', 'Template · approval') : t('Vorlage · Ablehnung', 'Template · refusal'), 'hint')), () => {
        testCase = scenario;
        renderRun();
        $('cases-panel').querySelector('[aria-pressed="true"]')?.focus();
      }, 'case-button');
      control.setAttribute('aria-pressed', String(scenario.id === testCase.id));
      return control;
    })),
    hint(t('Die Fälle liefern vorgegebene Prüffakten. Änderungen an Vergleichen und am Ausgang wirken sofort in der Vorschau.', 'These cases supply predefined facts. Changes to comparisons and responses appear immediately in the preview.'))
  );
  $('result-panel').replaceChildren(
    heading(t('Prüfnachweis', 'Evidence'), badge(t(...resultLabels[result.state]), result.state)),
    text('p', result.error ? localizeError(result.error) : reason, 'hint'),
    element('div', { className: 'trace-list' }, result.trace.map(step => {
      const check = rule.checks.find(item => item.fact === step.leftOperand);
      return element('div', { className: 'trace-row' },
        element('div', {}, text('strong', checkName(check)),
          text('small', t(`Ist ${display(step.actual)} · Soll ${localLabel(comparisonLabels, step.operator)} ${display(step.rightOperand)}`,
            `Actual ${display(step.actual)} · Expected ${localLabel(comparisonLabels, step.operator)} ${display(step.rightOperand)}`), 'hint')),
        badge(t(...stepLabels[step.state]), step.state));
    })),
    heading(t('POST /verify · Antwortvorschau', 'POST /verify · response preview'), badge(`HTTP ${preview.status}`)),
    json(preview.body),
    element('details', { className: 'source-links' }, text('summary', t('Spezifikationen', 'Specifications')),
      ...rule.sources.map(url => element('a', { href: url, target: '_blank', rel: 'noreferrer' }, new URL(url).hostname)))
  );
}

function render() {
  $('example-list').replaceChildren(...exampleIds.map((id, index) => {
    const item = button(element('span', { className: 'example-label' },
      text('span', String(index + 1).padStart(2, '0'), 'example-number'),
      text('span', t(...examples[id].title))), () => {
      showRule(id);
      $('example-list').querySelector('[aria-current="true"]')?.focus();
    }, 'example-button');
    if (id === rule.id) item.setAttribute('aria-current', 'true');
    return item;
  }));
  $('rule-title').textContent = t(...examples[rule.id].title);
  $('rule-description').textContent = t(...examples[rule.id].description);
  $('rule-format').textContent = localLabel(formatLabels, rule.appliesTo.format, rule.appliesTo.format);
  $('rule-type').textContent = rule.appliesTo.type;
  renderConfig();
  renderRun();
}

$('dialog-close').addEventListener('click', () => $('dialog').close());
$('export-rule').addEventListener('click', () => {
  const exportedRule = { ...rule };
  delete exportedRule.cases;
  const url = URL.createObjectURL(new Blob([JSON.stringify(exportedRule, null, 2) + '\n'], { type: 'application/json' }));
  element('a', { href: url, download: `${rule.id}.json` }).click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
});
$('reset-rule').addEventListener('click', () => {
  drafts.delete(rule.id);
  try { localStorage.removeItem(storagePrefix + rule.id); }
  catch { /* The in-memory draft has already been removed. */ }
  drafts.set(rule.id, structuredClone(source.get(rule.id)));
  showRule(rule.id);
});
document.querySelector('.skip-link').addEventListener('click', event => {
  event.preventDefault();
  $('workspace').focus();
});
window.addEventListener('hashchange', () => {
  const requested = location.hash.slice(1);
  if (source.has(requested) && rule?.id !== requested) showRule(requested);
});

try {
  await Promise.all(exampleIds.map(async id => {
    const response = await fetch(new URL(`../../examples/${id}.json`, import.meta.url));
    if (!response.ok) throw new Error(`${id} · HTTP ${response.status}`);
    source.set(id, await response.json());
  }));
  const requested = location.hash.slice(1);
  showRule(source.has(requested) ? requested : exampleIds[0]);
} catch (error) {
  loadError = error;
  renderLoadError();
  setStatus('ProofSieve über den lokalen HTTP-Server öffnen.', 'Open ProofSieve through the local HTTP server.');
}

function renderLoadError() {
  $('rule-title').textContent = t('Beispiele konnten nicht geladen werden', 'Unable to load examples');
  $('rule-description').textContent = loadError.message;
}

onLanguageChange(() => {
  if (rule) render();
  else if (loadError) renderLoadError();
  if (statusMessage) $('app-status').textContent = t(...statusMessage);
});
