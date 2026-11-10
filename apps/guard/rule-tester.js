import { onLanguageChange, t } from '../shared/i18n.js';

const FILE_LIMIT = 96 * 1024;
const FORMATS = {
  json: { title: 'JSON', accept: '.json,.txt,application/json,text/plain' },
  turtle: { title: 'Turtle', accept: '.ttl,.txt,text/turtle,text/plain' },
  'sd-jwt': { title: 'SD-JWT VC', accept: '.jwt,.sd-jwt,.txt,application/jwt,text/plain' },
  mdoc: { title: 'mdoc · CBOR/Base64url', accept: '.cbor,.mdoc,.txt,application/cbor,text/plain' },
  'jwt-vc': { title: 'W3C JWT-VC', accept: '.jwt,.txt,application/jwt,text/plain' },
  'vc-data-integrity': { title: 'W3C VC · Data Integrity', accept: '.json,.txt,application/json,text/plain' },
};
const GROUPS = {
  and: ['UND', 'AND', 'Alle Zweige müssen zutreffen', 'All branches must match'],
  or: ['ODER', 'OR', 'Mindestens ein Zweig muss zutreffen', 'At least one branch must match'],
  xone: ['GENAU EINS', 'EXACTLY ONE', 'Genau ein Zweig muss zutreffen', 'Exactly one branch must match'],
};
const OPERATORS = { eq: '=', neq: '≠', gt: '>', gteq: '≥', lt: '<', lteq: '≤' };
const REASONS = {
  comparison: ['Wert weicht ab', 'Value differs'],
  missing: ['Feld fehlt', 'Field missing'],
  type: ['Falscher Datentyp', 'Wrong data type'],
};
const VERIFICATION_PATHS = {
  local: ['Lokal', 'Local'],
  ocsp: ['Lokal + OCSP', 'Local + OCSP'],
  dss: ['Extern · DSS', 'External · DSS'],
  remote: ['Extern', 'External'],
};
const CHECK_OUTCOMES = {
  passed: ['Bestätigt', 'Verified'],
  failed: ['Abgelehnt', 'Failed'],
  indeterminate: ['Unbestimmt', 'Inconclusive'],
};

export function verificationPath(kind) {
  return Object.hasOwn(VERIFICATION_PATHS, kind) ? t(...VERIFICATION_PATHS[kind]) : kind;
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function drawTrace(trace) {
  const entry = node('li');
  const row = node('div', 'rule-tester-node');
  const badge = node('span', 'rule-tester-badge', trace.matched ? t('Erfüllt', 'Matched') : t('Nicht erfüllt', 'Unmatched'));
  badge.dataset.state = trace.matched ? 'pass' : 'fail';
  const copy = node('div', 'rule-tester-node-copy');
  if (trace.kind === 'group') {
    const [de, en, helpDe, helpEn] = GROUPS[trace.operator];
    copy.append(node('strong', '', t(de, en)), node('span', 'muted', t(helpDe, helpEn)));
  } else {
    const comparison = node('div', 'rule-tester-comparison');
    comparison.append(node('code', '', trace.field), node('span', '', OPERATORS[trace.operator]),
      node('code', '', trace.expectedText ?? JSON.stringify(trace.expected)));
    copy.append(comparison);
    const info = node('div', 'rule-tester-reason');
    if (Object.hasOwn(REASONS, trace.reason)) info.append(node('span', '', t(...REASONS[trace.reason])));
    if (typeof trace.actualText === 'string') {
      const actual = node('span', '', t('Istwert ', 'Actual '));
      actual.append(node('code', '', trace.actualText));
      info.append(actual);
    }
    if (info.childNodes.length) copy.append(info);
  }
  row.append(copy, badge);
  entry.append(row);
  if (trace.kind === 'group') {
    const children = node('ul', 'rule-tester-branches');
    children.append(...trace.children.map(drawTrace));
    entry.append(children);
  }
  return entry;
}

async function readInputFile(file, format) {
  if (file.size > FILE_LIMIT) throw new Error(t('Die Datei ist größer als 96 KiB.', 'The file exceeds 96 KiB.'));
  if (format !== 'mdoc') return new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
  const bytes = new Uint8Array(await file.arrayBuffer());
  const text = new TextDecoder().decode(bytes).trim();
  if (/^[A-Za-z0-9_-]+={0,2}$/.test(text)) return text;
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function createRuleTester(dialog) {
  dialog.classList.add('rule-tester');
  dialog.setAttribute('aria-labelledby', 'rule-tester-title');
  dialog.innerHTML = `
    <header class="rule-tester-header">
      <div>
        <span class="rule-tester-eyebrow" data-copy="draft"></span>
        <h2 id="rule-tester-title" data-copy="title"></h2>
        <p class="muted" data-copy="intro"></p>
      </div>
      <button type="button" data-role="close" data-copy="close"></button>
    </header>
    <div class="rule-tester-columns">
      <section class="rule-tester-input" aria-labelledby="rule-tester-input-title">
        <div class="rule-tester-section-heading">
          <h3 id="rule-tester-input-title" data-copy="input"></h3>
          <code class="rule-tester-format" data-role="format"></code>
        </div>
        <label for="rule-tester-data" data-copy="dataLabel"></label>
        <textarea id="rule-tester-data" data-role="data" spellcheck="false" autocomplete="off" rows="13"></textarea>
        <div class="actions">
          <button type="button" data-role="file-button" data-copy="file"></button>
          <input type="file" data-role="file" hidden>
          <button type="button" data-role="run" data-copy="run"></button>
        </div>
        <div class="actions" data-role="examples" hidden>
          <button type="button" data-role="valid" data-copy="valid"></button>
          <button type="button" data-role="tampered" data-copy="tampered"></button>
        </div>
        <p class="rule-tester-file-error" data-role="file-error" role="alert" hidden></p>
      </section>
      <section class="rule-tester-output" aria-labelledby="rule-tester-output-title">
        <div class="rule-tester-section-heading">
          <h3 id="rule-tester-output-title" data-copy="result"></h3>
          <span class="rule-tester-live" data-role="evaluation-mode"></span>
        </div>
        <p class="rule-tester-status" data-role="status" role="status"></p>
        <div data-role="result"></div>
      </section>
    </div>`;

  const copy = {
    draft: ['VORSCHAU', 'PREVIEW'],
    title: ['Regel testen', 'Test rule'],
    intro: ['Der Guard wertet den aktuellen Entwurf mit deiner Testeingabe aus.', 'The Guard evaluates the current draft against your test input.'],
    close: ['Schließen', 'Close'],
    input: ['Testeingabe', 'Test input'],
    dataLabel: ['Credential oder Prüfdaten', 'Credential or verification data'],
    file: ['Datei laden', 'Load file'],
    run: ['Jetzt prüfen', 'Run now'],
    valid: ['Signiertes Original laden', 'Load signed original'],
    tampered: ['Manipulierten Fall laden', 'Load tampered case'],
    result: ['Ergebnis', 'Result'],
  };
  const get = role => dialog.querySelector(`[data-role="${role}"]`);
  const input = get('data');
  const fileInput = get('file');
  const status = get('status');
  const output = get('result');
  let session = null;
  let view = { kind: 'idle' };
  let generation = 0;
  let fileSelection = 0;
  let timer;
  let controller;

  function renderDecision(result) {
    if (result.stage === 'credential') {
      const explanation = node('p', 'rule-tester-notice', t(
        'Der Guard hat das Credential abgelehnt. Die Regelauswertung wurde übersprungen.',
        'The Guard rejected the credential and skipped policy evaluation.',
      ));
      output.append(explanation);
    } else if (result.credentialVerified) {
      output.append(node('p', 'rule-tester-notice', t('Credential geprüft · Regel auf verifizierte Claims angewandt',
        'Credential verified · Policy evaluated against verified claims')));
    }

    if (result.stage === 'verification') {
      output.append(node('p', 'rule-tester-notice', t(
        'Die erforderliche Zahl bestätigter Signaturen wurde nicht erreicht. ODRL-Auswertung übersprungen.',
        'The required number of verified signatures was not reached. ODRL evaluation was skipped.',
      )));
    }
    if (Array.isArray(result.checks) && result.checks.length) {
      output.append(node('h3', 'rule-tester-checks-heading', t('Signaturprüfungen', 'Signature checks')));
      const list = node('ul', 'rule-tester-tree');
      for (const check of result.checks) {
        const item = node('li', 'rule-tester-check');
        const row = node('div', 'rule-tester-node');
        const details = node('div', 'rule-tester-node-copy');
        details.append(node('strong', '', check.signer), node('span', 'muted', [
          verificationPath(check.kind), check.connector, check.connectorProfile,
        ].filter(Boolean).join(' · ')));
        const reason = [check.reason, check.reportId].filter(Boolean).join(' · ');
        if (reason) details.append(node('code', '', reason));
        const label = Object.hasOwn(CHECK_OUTCOMES, check.outcome)
          ? t(...CHECK_OUTCOMES[check.outcome]) : check.outcome;
        const badge = node('span', 'rule-tester-badge', label);
        badge.dataset.state = check.outcome === 'passed' ? 'pass' : check.outcome === 'failed' ? 'fail' : 'indeterminate';
        row.append(details, badge);
        item.append(row);
        list.append(item);
      }
      output.append(list);
    }

    if (result.trace) {
      const tree = node('ul', 'rule-tester-tree');
      tree.append(drawTrace(result.trace));
      output.append(tree);
    }

    const destination = result.decision?.redirectUrl;
    if (typeof destination === 'string') {
      const url = node('div', 'rule-tester-destination');
      url.append(node('strong', '', t('Ziel-URL', 'Destination URL')), node('code', '', destination));
      output.append(url);
    }
    const response = node('details', 'rule-tester-response');
    response.append(node('summary', '', t('Antwortvorschau', 'Response preview')),
      node('pre', '', JSON.stringify(result.decision, null, 2)));
    response.open = result.stage !== 'policy';
    output.append(response);
  }

  function render() {
    output.replaceChildren();
    status.dataset.state = view.kind;
    const evaluationMode = get('evaluation-mode');
    evaluationMode.dataset.manual = session?.manual ? 'true' : 'false';
    evaluationMode.textContent = session?.manual ? t('Manuell', 'Manual') : 'Live';
    if (view.kind === 'result') {
      const result = view.result;
      const inconclusive = result.decision?.outcome === 'indeterminate';
      const decision = inconclusive ? t('Unbestimmt', 'Inconclusive')
        : result.valid ? t('Freigegeben', 'Allowed') : t('Abgelehnt', 'Denied');
      const value = typeof result.decision === 'boolean' ? ` · ${result.decision}` : '';
      status.dataset.state = inconclusive ? 'indeterminate' : result.valid ? 'pass' : 'fail';
      status.textContent = `${decision} · HTTP ${result.decisionStatus}${value}`;
      renderDecision(result);
    } else if (view.kind === 'error') {
      status.textContent = view.message;
    } else if (view.kind === 'running') {
      status.textContent = t('Guard prüft die Eingabe …', 'The Guard is checking the input …');
    } else {
      status.textContent = session?.manual && input.value.trim()
        ? t('Starte die Dokumentprüfung mit „Jetzt prüfen“. Dabei können konfigurierte Prüfdienste aufgerufen werden.',
          'Select “Run now” to verify the document. This may contact configured check services.')
        : t('Füge Prüfdaten ein oder lade eine Datei.', 'Paste test data or load a file.');
    }
  }

  function cancel() {
    generation += 1;
    clearTimeout(timer);
    controller?.abort();
  }

  function schedule(delay = 250) {
    cancel();
    const text = input.value;
    const run = generation;
    view = { kind: text.trim() ? 'running' : 'idle' };
    render();
    if (!text.trim()) return;
    timer = setTimeout(async () => {
      controller = new AbortController();
      try {
        const result = await session.test(text, controller.signal);
        if (run !== generation || !dialog.open) return;
        view = { kind: 'result', result };
      } catch (error) {
        if (run !== generation || !dialog.open) return;
        view = { kind: 'error', message: error?.message || t('Prüfung fehlgeschlagen.', 'Verification failed.') };
      }
      render();
    }, delay);
  }

  function onInput() {
    get('file-error').hidden = true;
    if (session?.manual) {
      cancel();
      view = { kind: 'idle' };
      render();
    } else {
      schedule();
    }
  }

  function load(text) {
    input.value = text;
    onInput();
  }

  function translate() {
    for (const element of dialog.querySelectorAll('[data-copy]')) element.textContent = t(...copy[element.dataset.copy]);
    if (dialog.open) render();
  }

  get('close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => {
    if (dialog.open) return;
    cancel();
    session = null;
    input.value = '';
    view = { kind: 'idle' };
    render();
  });
  input.addEventListener('input', onInput);
  get('run').addEventListener('click', () => schedule(0));
  get('valid').addEventListener('click', () => load(session.examples.valid));
  get('tampered').addEventListener('click', () => load(session.examples.tampered));
  get('file-button').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const [file] = fileInput.files;
    fileInput.value = '';
    if (!file || !session) return;
    const selection = ++fileSelection;
    const loadGeneration = generation;
    const isCurrentFile = () => selection === fileSelection && loadGeneration === generation && dialog.open;
    const message = get('file-error');
    message.hidden = true;
    try {
      const text = await readInputFile(file, session.format);
      if (isCurrentFile()) load(text);
    } catch (error) {
      if (!isCurrentFile()) return;
      message.textContent = error instanceof TypeError
        ? t('Wähle eine UTF-8-Textdatei für dieses Format.', 'Choose a UTF-8 text file for this format.') : error.message;
      message.hidden = false;
    }
  });

  onLanguageChange(translate);
  translate();

  return {
    open(options) {
      if (dialog.open) return;
      session = options;
      const format = FORMATS[options.format];
      get('format').textContent = format.title;
      fileInput.accept = format.accept;
      get('examples').hidden = !options.examples;
      dialog.showModal();
      load(options.input);
      input.focus();
    },
  };
}
