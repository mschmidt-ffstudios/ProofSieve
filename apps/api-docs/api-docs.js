import { onLanguageChange, t } from '../shared/i18n.js';
import { localizeSwagger } from './swagger-language.js';

const login = document.getElementById('api-login');
const tokenInput = document.getElementById('api-token');
const signIn = document.getElementById('api-sign-in');
const signOut = document.getElementById('api-sign-out');
const download = document.getElementById('api-download');
const actions = document.getElementById('api-actions');
const curlAuth = document.getElementById('api-curl-auth');
const status = document.getElementById('api-status');
const explorer = document.getElementById('api-explorer');
const endpointPath = /^\/verify(?:\/[A-Za-z0-9_-]+)*$/;
const operationId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const decisionId = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const tokenPattern = /^(?:[A-Za-z0-9_-]{43}|[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;
let session = null;
let message = null;

function report(copy, error = false) {
  message = copy;
  status.textContent = copy ? t(...copy) : '';
  status.dataset.error = String(error);
}

function render(spec, token) {
  const paths = Object.keys(spec.paths).filter(path => path !== '/evidence');
  const evidence = Object.hasOwn(spec.paths, '/evidence');
  if (!paths.every(path => endpointPath.test(path) && spec.paths[path]?.post)) {
    throw new Error('Unexpected verification paths');
  }
  if (evidence && (!token || spec.paths['/evidence']?.get?.operationId !== 'exportEvidence'
      || Object.keys(spec.paths['/evidence']).length !== 1)) {
    throw new Error('Unexpected evidence export path');
  }
  const current = { token, spec, paths: new Set(paths) };
  if (paths.length || evidence) {
    const components = { ...spec.components };
    delete components.securitySchemes;
    window.SwaggerUIBundle({
      domNode: explorer,
      spec: { ...spec, components, security: [], servers: [{ url: location.origin }] },
      layout: 'BaseLayout',
      validatorUrl: null,
      queryConfigEnabled: false,
      persistAuthorization: false,
      showMutatedRequest: false,
      supportedSubmitMethods: evidence ? ['post', 'get'] : ['post'],
      requestInterceptor(request) {
        const url = new URL(request.url, location.origin);
        const method = request.method.toUpperCase();
        const verification = method === 'POST' && !url.search && current.paths.has(url.pathname);
        const exportRequest = evidence && method === 'GET' && url.pathname === '/evidence'
          && allowedEvidenceQuery(url.searchParams, current.paths);
        if (session !== current || url.origin !== location.origin || url.hash || !(verification || exportRequest)) {
          throw new Error('Request outside the current verification session');
        }
        const headers = { ...request.headers };
        if (current.token) headers.Authorization = `Bearer ${current.token}`;
        return { ...request, headers, mode: 'same-origin', credentials: 'omit', redirect: 'error' };
      },
    });
  }
  session = current;
  actions.hidden = false;
  signOut.hidden = !token;
  curlAuth.hidden = !token;
  login.hidden = true;
  report(paths.length
    ? ['Die Konsole zeigt die freigegebenen Prüfendpunkte dieser Sitzung.', 'The console shows the verification endpoints granted to this session.']
    : ['Für diese Sitzung ist kein Prüfendpunkt freigegeben.', 'No verification endpoint is granted to this session.']);
  if (token) download.focus();
}

function allowedEvidenceQuery(query, paths) {
  const keys = [...query.keys()];
  return keys.length === new Set(keys).size
    && keys.every(key => ['endpoint', 'operationId', 'decisionId'].includes(key))
    && paths.has(query.get('endpoint'))
    && operationId.test(query.get('operationId') ?? '')
    && (!query.has('decisionId') || decisionId.test(query.get('decisionId')));
}

async function load(token = null) {
  report(['Prüfendpunkte werden geladen …', 'Loading verification endpoints …']);
  signIn.disabled = true;
  try {
    const headers = { Accept: 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch('/openapi.json', {
      headers, mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
    });
    if (response.status === 401) {
      login.hidden = false;
      report(token ? ['Der Zugriffstoken wurde abgelehnt.', 'The access token was rejected.'] : null, Boolean(token));
      tokenInput.focus();
      return;
    }
    if (!response.ok) throw new Error('OpenAPI unavailable');
    render(await response.json(), token);
  } catch {
    login.hidden = false;
    report(['Die API-Beschreibung konnte nicht geladen werden.', 'The API description could not be loaded.'], true);
  } finally {
    signIn.disabled = false;
  }
}

login.addEventListener('submit', event => {
  event.preventDefault();
  if (signIn.disabled) return;
  const token = tokenInput.value.trim();
  tokenInput.value = '';
  if (token.length > tokenInput.maxLength || !tokenPattern.test(token)) {
    report(['Gib einen gültigen Zugriffstoken ein.', 'Enter a valid access token.'], true);
    return;
  }
  void load(token);
});

signOut.addEventListener('click', () => {
  if (!session) return;
  session.token = null;
  session = null;
  explorer.replaceChildren();
  actions.hidden = true;
  curlAuth.hidden = true;
  login.hidden = false;
  tokenInput.focus();
  report(null);
});

download.addEventListener('click', () => {
  if (!session) return;
  const blob = new Blob([JSON.stringify(session.spec, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'proofsieve-openapi.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

onLanguageChange(() => { status.textContent = message ? t(...message) : ''; });
localizeSwagger(explorer);
void load();
