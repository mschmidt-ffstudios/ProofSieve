import { t, onLanguageChange } from '../shared/i18n.js';

const MAX_INPUT_BYTES = 64 * 1024;
const MAX_REQUEST_BYTES = 96 * 1024;
const DRAFT_KEY = 'proofsieve:builder-draft:v1';
const HANDOFF_KEY = 'proofsieve:guard-input:v1';
const encoder = new TextEncoder();
const bytes = text => encoder.encode(text).length;
const pretty = value => JSON.stringify(value, null, 2);
const get = id => document.getElementById(`builder-${id}`);

function problem(de, en) {
  return Object.assign(new Error(t(de, en)), { copy: [de, en] });
}

function requireJsonObject(text, de, en) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw problem(`${de} braucht gültiges JSON.`, `${en} must contain valid JSON.`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw problem(`${de} braucht ein JSON-Objekt.`, `${en} must be a JSON object.`);
  }
}

function turtleIri(value) {
  if (!/^[a-z][a-z0-9+.-]*:[^\s<>"{}|^`\\\u0000-\u001f]+$/i.test(value)) {
    throw problem('Knoten und Eigenschaft brauchen jeweils eine absolute IRI.', 'The node and property each need an absolute IRI.');
  }
  return `<${value}>`;
}

const statusField = { name: 'status', label: ['Status', 'Status'], value: 'active' };
const presets = {
  status: {
    language: 'odrl',
    help: [
      'Der Standard-Guard akzeptiert den Status active. Mit blocked kannst du die Ablehnung ausprobieren.',
      'The default Guard accepts the active status. Try blocked to see a denial.',
    ],
    fields: [statusField],
    build: ({ status }) => pretty({ status }),
  },
  credential: {
    language: 'odrl',
    help: [
      'Diese unsignierten Testdaten enthalten frei editierbare Felder für eine ODRL-Regel.',
      'This unsigned test data contains editable fields for an ODRL rule.',
    ],
    fields: [
      { name: 'issuer', label: ['Aussteller', 'Issuer'], value: 'did:web:issuer.example' },
      { name: 'type', label: ['Nachweistyp', 'Credential type'], value: 'MemberCredential' },
      { name: 'subject', label: ['Subjekt', 'Subject'], value: 'did:web:member.example' },
      { name: 'claims', label: ['Angaben als JSON-Objekt', 'Claims as a JSON object'], value: pretty({ department: 'Demo', active: true }), multiline: true },
    ],
    build: ({ issuer, type, subject, claims }) => {
      requireJsonObject(claims, 'Das Feld Angaben', 'The claims field');
      // Preserve the claims' numeric tokens and duplicate fields for server validation.
      return [
        '{',
        `  "issuer": ${JSON.stringify(issuer)},`,
        `  "type": ${JSON.stringify(type)},`,
        `  "subject": ${JSON.stringify(subject)},`,
        `  "claims": ${claims.trim().replaceAll('\n', '\n  ')}`,
        '}',
      ].join('\n');
    },
  },
  turtle: {
    language: 'shacl',
    help: [
      'Knoten, Eigenschaft und Status passen zur SHACL-Vorlage im Guard. Die Regel prüft den Status des Knotens.',
      'The node, property and status match the Guard’s SHACL template, which checks the node’s status.',
    ],
    fields: [
      { name: 'subject', label: ['Knoten-IRI', 'Node IRI'], value: 'https://proofsieve.example/demo/request' },
      { name: 'predicate', label: ['Eigenschafts-IRI', 'Property IRI'], value: 'https://proofsieve.example/demo/status' },
      statusField,
    ],
    build: ({ subject, predicate, status }) => `${turtleIri(subject)} ${turtleIri(predicate)} ${JSON.stringify(status)} .`,
  },
};

const picker = get('preset');
const input = get('input');
const fields = get('fields');
const status = get('status');
const preview = get('preview');
const save = get('save');
const deleteDraft = get('delete-draft');
const download = get('export');
const handoff = get('handoff');
const sampleOptions = get('samples');
const sampleRun = get('sample-run');
const sampleToken = get('sample-token');
const sampleAuth = get('sample-auth');
const sampleCatalog = new Map();

try {
  const response = await fetch('/examples/credentials.json');
  if (!response.ok) throw new Error();
  for (const sample of await response.json()) {
    const option = document.createElement('option');
    option.value = sample.id;
    sampleOptions.append(option);
    sampleCatalog.set(sample.id, { sample, option });
    presets[sample.id] = {
      language: 'odrl',
      help: [sample.representation.de, sample.representation.en],
      fields: [],
      build: () => pretty(sample.input),
      sample,
    };
  }
  sampleOptions.hidden = !sampleCatalog.size;
} catch {
  get('samples-load-error').hidden = false;
}

const drafts = new Map(Object.entries(presets).map(([id, preset]) => {
  const values = Object.fromEntries(preset.fields.map(field => [field.name, field.value]));
  return [id, { values, appliedValues: { ...values }, text: preset.build(values) }];
}));
let current = 'status';
let statusCopy = ['Wähle eine Vorlage oder bearbeite die Eingabe direkt.', 'Choose a template or edit the input directly.'];
let sampleCheck = null;
let inputRevision = 0;

function showSampleAuth() {
  sampleAuth.hidden = false;
}

void fetch('/auth/me', { mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store' })
  .then(response => { if (response.status === 401) showSampleAuth(); })
  .catch(() => { /* A failed probe leaves the explicit check available. */ });

get('sample-clear-token').addEventListener('click', () => {
  sampleToken.value = '';
  sampleToken.focus();
});

function report(copy, state = 'info') {
  statusCopy = copy;
  status.textContent = t(...copy);
  status.dataset.state = state;
}

function hasPendingTemplate() {
  const { values, appliedValues } = drafts.get(current);
  return !appliedValues || Object.entries(values).some(([name, value]) => value !== appliedValues[name]);
}

function refreshPreview() {
  const text = input.value;
  const inputBytes = bytes(text);
  get('size').textContent = `${inputBytes} / ${MAX_INPUT_BYTES} Bytes`;
  const pending = hasPendingTemplate();
  get('pending').hidden = !pending;
  get('discard-fields').hidden = !pending;
  if (pending) {
    preview.textContent = t('Übernimm oder verwirf die Vorlagenänderungen für die aktuelle Vorschau.',
      'Apply or discard the template changes to preview the current request.');
    save.disabled = download.disabled = handoff.disabled = sampleRun.disabled = true;
    return;
  }
  save.disabled = inputBytes > MAX_INPUT_BYTES;

  let error = '';
  try {
    if (inputBytes > MAX_INPUT_BYTES) throw problem('Die Eingabe überschreitet 64 KiB.', 'The input exceeds 64 KiB.');
    const { language } = presets[current];
    if (!text.trim()) throw problem('Gib einen Prüfinput ein.', 'Enter input to verify.');
    if (language === 'odrl') requireJsonObject(text, 'Der Prüfinput', 'The input');
    const payload = language === 'odrl' ? text : JSON.stringify(text);
    if (bytes(`{"data":${payload}}`) > MAX_REQUEST_BYTES) {
      throw problem('Die verpackte API-Anfrage überschreitet 96 KiB.', 'The full API request exceeds 96 KiB.');
    }
    preview.textContent = `{\n  "data": ${payload}\n}`;
  } catch (problem) {
    error = problem.message;
    preview.textContent = error;
  }
  download.disabled = Boolean(error);
  handoff.disabled = Boolean(error);
  sampleRun.disabled = Boolean(error) || Boolean(sampleCheck?.pending);
}

function renderSampleResult() {
  const message = get('sample-message');
  const response = get('sample-response');
  const error = get('sample-error');
  message.closest('.result').dataset.state = sampleCheck?.state ?? '';
  message.textContent = sampleCheck
    ? t(...sampleCheck.copy)
    : t('Noch keine Serverantwort', 'No server response yet');
  response.textContent = sampleCheck?.response ?? '';
  error.textContent = sampleCheck?.error ?? '';
  error.hidden = !error.textContent;
}

function renderSampleOptions() {
  sampleOptions.label = t('Credential-Beispiele mit Quelle', 'Credential examples with sources');
  for (const { sample, option } of sampleCatalog.values()) {
    option.textContent = t(sample.title.de, sample.title.en);
  }
}

function renderPresetCopy() {
  const preset = presets[current];
  get('preset-help').textContent = t(...preset.help);
  get('input-label').textContent = preset.language === 'odrl'
    ? t('Prüfinput als JSON', 'JSON input')
    : t('Prüfinput als Turtle', 'Turtle input');
  get('input-help').textContent = preset.sample
    ? t('Die JSON-Daten lassen sich direkt bearbeiten.', 'Edit the JSON data directly.')
    : t(
      'Die Rohdaten lassen sich direkt bearbeiten. Die Übernahme der Vorlagenwerte ersetzt den Text.',
      'Edit the raw data directly. Applying the template values replaces the current text.',
    );
  fields.querySelectorAll('label > span').forEach((caption, index) => {
    caption.textContent = t(...preset.fields[index].label);
  });
}

function changePreset(id) {
  current = id;
  picker.value = id;
  const preset = presets[id];
  const draft = drafts.get(id);
  const sample = preset.sample;
  get('sample-details').hidden = !sample;
  get('sample-check').hidden = !sample;
  const signedEndpoint = sample?.signedDemoEndpoint;
  const signedLink = get('sample-signed-link');
  const hasSignedDemo = typeof signedEndpoint === 'string' && /^\/verify\/demo\/[a-z0-9-]+$/.test(signedEndpoint);
  get('sample-signed').hidden = !hasSignedDemo;
  if (hasSignedDemo) {
    signedLink.href = `/apps/guard/?${new URLSearchParams({ endpoint: signedEndpoint, case: 'original' })}`;
  } else {
    signedLink.removeAttribute('href');
  }
  get('preview-help').hidden = Boolean(sample);
  get('form').hidden = Boolean(sample);
  if (sample) {
    const source = get('sample-source');
    source.textContent = sample.source.label;
    source.href = sample.source.url;
    get('sample-format').textContent = sample.format;
    get('sample-condition').textContent = `field:${sample.check.field} eq ${JSON.stringify(sample.check.expected)}`;
  }
  fields.replaceChildren(...preset.fields.map(field => {
    const label = document.createElement('label');
    const caption = document.createElement('span');
    const control = document.createElement(field.multiline ? 'textarea' : 'input');
    control.name = field.name;
    control.value = draft.values[field.name];
    control.required = true;
    control.maxLength = field.multiline ? MAX_INPUT_BYTES : 512;
    control.autocomplete = 'off';
    control.spellcheck = false;
    label.append(caption, control);
    return label;
  }));
  setInput(draft.text);
  renderPresetCopy();
}

function setInput(text) {
  inputRevision++;
  input.value = text;
  drafts.get(current).text = text;
  sampleCheck = null;
  renderSampleResult();
  refreshPreview();
}

window.addEventListener('pagehide', () => { sampleToken.value = ''; });

picker.addEventListener('change', () => {
  sampleToken.value = '';
  changePreset(picker.value);
  report(['Vorlage gewechselt.', 'Template changed.']);
});

fields.addEventListener('input', event => {
  const { name, value } = event.target;
  drafts.get(current).values[name] = value;
  refreshPreview();
});

get('form').addEventListener('submit', event => {
  event.preventDefault();
  try {
    const draft = drafts.get(current);
    const text = presets[current].build(draft.values);
    if (bytes(text) > MAX_INPUT_BYTES) throw problem('Die erzeugte Eingabe überschreitet 64 KiB.', 'The generated input exceeds 64 KiB.');
    draft.appliedValues = { ...draft.values };
    setInput(text);
    report(['Vorlagenwerte übernommen.', 'Template values applied.'], 'success');
  } catch (error) {
    report(error.copy ?? ['Die Vorlage konnte nicht übernommen werden.', 'The template could not be applied.'], 'error');
  }
});

get('discard-fields').addEventListener('click', () => {
  const draft = drafts.get(current);
  draft.appliedValues ??= Object.fromEntries(presets[current].fields.map(({ name, value }) => [name, value]));
  draft.values = { ...draft.appliedValues };
  for (const control of fields.querySelectorAll('[name]')) control.value = draft.values[control.name];
  get('form').querySelector('[type="submit"]').focus();
  refreshPreview();
  report(['Vorlagenänderungen verworfen. Der Prüfinput wurde beibehalten.', 'Template changes discarded. The verification input was kept.']);
});

input.addEventListener('input', () => {
  setInput(input.value);
  report(['Prüfinput geändert.', 'Verification input changed.']);
});

get('sample-original').addEventListener('click', () => {
  setInput(pretty(presets[current].sample.input));
  report(['Beispieldaten geladen.', 'Example data loaded.']);
});

get('sample-negative').addEventListener('click', () => {
  const { input, check } = presets[current].sample;
  setInput(pretty({ ...input, [check.field]: check.negative }));
  report(['Gegenprobe geladen. Führe die Beispielprüfung erneut aus.', 'Counterexample loaded. Run the example check again.']);
});

sampleRun.addEventListener('click', async () => {
  const sample = presets[current].sample;
  const token = sampleAuth.hidden ? '' : sampleToken.value.trim();
  sampleToken.value = '';
  if (!sampleAuth.hidden && !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    sampleCheck = {
      copy: ['Gib den Admin-Zugriffstoken für diese Beispielprüfung ein.', 'Enter the admin access token for this example check.'],
      state: 'error',
    };
    renderSampleResult();
    sampleToken.focus();
    return;
  }
  const request = {
    pending: true,
    copy: ['Beispielprüfung läuft …', 'Checking example…'],
  };
  sampleCheck = request;
  sampleRun.disabled = true;
  renderSampleResult();
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(`/examples/credentials/${sample.id}/check`, {
      method: 'POST',
      headers,
      mode: 'same-origin', credentials: 'omit', redirect: 'error',
      body: preview.textContent,
    });
    const result = await response.json();
    if (sampleCheck !== request) return;
    if (response.ok && typeof result === 'boolean') {
      sampleCheck = {
        copy: result
          ? ['ODRL-Bedingung erfüllt', 'ODRL condition met']
          : ['ODRL-Bedingung nicht erfüllt', 'ODRL condition not met'],
        response: `HTTP ${response.status} · ${result}`,
        state: result ? 'pass' : 'fail',
      };
    } else if (response.status === 401 || response.status === 403) {
      showSampleAuth();
      sampleCheck = {
        copy: response.status === 401
          ? ['Der Server braucht einen gültigen Admin-Zugriffstoken.', 'The server requires a valid admin access token.']
          : ['Die Beispielprüfung braucht Admin-Zugriff auf alle Endpunkte.', 'Example checks require admin access to all endpoints.'],
        response: `HTTP ${response.status}`,
        state: 'error',
      };
      sampleToken.focus();
    } else {
      sampleCheck = {
        copy: ['Der Server konnte die Eingabe nicht prüfen.', 'The server could not check the input.'],
        response: `HTTP ${response.status}`,
        error: result?.error,
        state: 'error',
      };
    }
  } catch {
    if (sampleCheck !== request) return;
    sampleCheck = {
      copy: ['Die Beispielprüfung ist nicht erreichbar.', 'The example check is unavailable.'],
      state: 'error',
    };
  }
  renderSampleResult();
  refreshPreview();
});

get('import').addEventListener('change', async event => {
  const [file] = event.target.files;
  event.target.value = '';
  if (!file) return;
  const revision = ++inputRevision;
  try {
    if (file.size > MAX_INPUT_BYTES) throw problem('Die Datei überschreitet 64 KiB.', 'The file exceeds 64 KiB.');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
    if (revision !== inputRevision) return;
    if (presets[current].language === 'odrl') requireJsonObject(text, 'Die Datei', 'The file');
    setInput(text);
    report(['Datei als Prüfinput übernommen.', 'File loaded as verification input.'], 'success');
  } catch (error) {
    if (revision !== inputRevision) return;
    report(error.copy ?? ['Die Datei konnte nicht gelesen werden.', 'The file could not be read.'], 'error');
  }
});

save.addEventListener('click', () => {
  try {
    const { text, values } = drafts.get(current);
    localStorage.setItem(DRAFT_KEY, JSON.stringify({ preset: current, text, values, templateResolved: true }));
    deleteDraft.hidden = false;
    report(['Entwurf in diesem Browser gespeichert.', 'Draft saved in this browser.'], 'success');
  } catch {
    report(['Der Browser konnte den Entwurf nicht speichern.', 'The browser could not save the draft.'], 'error');
  }
});

deleteDraft.addEventListener('click', () => {
  try {
    localStorage.removeItem(DRAFT_KEY);
    deleteDraft.hidden = true;
    (save.disabled ? input : save).focus();
    report(['Gespeicherten Entwurf aus diesem Browser gelöscht.', 'Saved draft removed from this browser.'], 'success');
  } catch {
    report(['Der Browser konnte den gespeicherten Entwurf nicht löschen.',
      'The browser could not delete the saved draft.'], 'error');
  }
});

window.addEventListener('storage', event => {
  if (event.storageArea === localStorage && (event.key === DRAFT_KEY || event.key === null)) {
    deleteDraft.hidden = event.newValue === null;
  }
});

download.addEventListener('click', () => {
  const isJson = presets[current].language === 'odrl';
  const blob = new Blob([input.value], { type: isJson ? 'application/json' : 'text/turtle;charset=utf-8' });
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = `proofsieve-${current}.${isJson ? 'json' : 'ttl'}`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
});

handoff.addEventListener('click', () => {
  try {
    sessionStorage.setItem(HANDOFF_KEY, JSON.stringify({ language: presets[current].language, text: input.value }));
  } catch {
    report(['Der Browser konnte die Übergabe nicht vorbereiten.', 'The browser could not prepare the handoff.'], 'error');
    return;
  }
  location.assign('/apps/guard/');
});

const exampleId = new URLSearchParams(location.search).get('example');
const requestedExample = sampleCatalog.has(exampleId) ? exampleId : null;
try {
  const stored = localStorage.getItem(DRAFT_KEY);
  deleteDraft.hidden = stored === null;
  const saved = JSON.parse(stored);
  if (saved && drafts.has(saved.preset) && typeof saved.text === 'string' && bytes(saved.text) <= MAX_INPUT_BYTES) {
    const draft = drafts.get(saved.preset);
    draft.text = saved.text;
    for (const name of Object.keys(draft.values)) {
      if (typeof saved.values?.[name] === 'string') draft.values[name] = saved.values[name];
    }
    if (presets[saved.preset].fields.length) {
      // Older drafts could store new field values alongside an unrelated raw input.
      draft.appliedValues = null;
      try {
        if (saved.templateResolved === true || presets[saved.preset].build(draft.values) === draft.text) {
          draft.appliedValues = { ...draft.values };
        }
      } catch { /* Invalid legacy template fields still need an explicit resolution. */ }
    }
    if (!requestedExample || requestedExample === saved.preset) {
      current = saved.preset;
      report(['Lokalen Entwurf wiederhergestellt.', 'Local draft restored.'], 'success');
    }
  }
} catch {
  report(['Lokaler Entwurf konnte nicht geladen werden. Die Vorlage ist geöffnet.', 'The local draft could not be loaded. The template is open.']);
}
renderSampleOptions();
if (requestedExample && requestedExample !== current) {
  report(['Credential-Beispiel geladen.', 'Credential example loaded.']);
}
changePreset(requestedExample ?? current);
status.textContent = t(...statusCopy);
onLanguageChange(() => {
  status.textContent = t(...statusCopy);
  renderSampleOptions();
  renderPresetCopy();
  renderSampleResult();
  refreshPreview();
});
