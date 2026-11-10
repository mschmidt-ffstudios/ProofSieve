import { onLanguageChange, t } from '../shared/i18n.js';

// Swagger UI 5.34.1 exposes English controls. Scope these translations to its
// chrome so API descriptions, schema names, editor values and responses stay intact.
const controls = [
  ['.try-out__btn', { 'Try it out': 'Ausprobieren', Cancel: 'Abbrechen', Reset: 'Zurücksetzen' }],
  ['.opblock-control__btn', { Execute: 'Ausführen', Clear: 'Antwort leeren' }],
  ['.download-contents', { Download: 'Herunterladen' }],
  ['.tablinks', { 'Edit Value': 'Wert bearbeiten', 'Example Value': 'Beispielwert' }],
  ['.examples-select__section-label', { 'Examples:': 'Beispiele:' }],
  ['.examples-select-element > option', { '[Modified value]': '[Geänderter Wert]' }],
  ['.servers-title', { Servers: 'Server' }],
  ['.models-control > span', { Schemas: 'Schemata' }],
  ['.json-schema-2020-12-expand-deep-button', { 'Expand all': 'Alle aufklappen', 'Collapse all': 'Alle zuklappen' }],
  ['.opblock-section-header .opblock-title, .responses-inner h4', {
    Parameters: 'Parameter', 'Request body': 'Anfragetext', Responses: 'Antworten', 'Server response': 'Serverantwort',
  }],
  ['.opblock-description-wrapper > p', { 'No parameters': 'Keine Parameter' }],
  ['.parameters th, .responses-header > td', { Description: 'Beschreibung' }],
  ['.response-col_links > i', { 'No links': 'Keine Links' }],
  ['.response-control-examples__title', { Examples: 'Beispiele' }],
  ['.response-control-media-type__title', { 'Media type': 'Medientyp' }],
  ['.response-control-media-type__accept-message', { Controls: 'Steuert den', 'header.': 'Header.' }],
  ['.request-url > h4', { 'Request URL': 'Anfrage-URL' }],
  ['.live-responses-table h5', { 'Response body': 'Antworttext', 'Response headers': 'Antwort-Header' }],
  ['.response-undocumented > i', { Undocumented: 'Nicht dokumentiert' }],
  ['.validation-errors', { 'Please correct the following validation errors and try again.':
    'Behebe die folgenden Eingabefehler und versuche es erneut.' }],
  ['.validation-errors li', {
    "For 'endpoint': Required field is not provided.": 'Für „endpoint“ fehlt ein Wert.',
    "For 'operationId': Required field is not provided.": 'Für „operationId“ fehlt ein Wert.',
  }],
];

const attributes = [
  ['.expand-operation', { 'Expand operation': 'Abschnitt aufklappen', 'Collapse operation': 'Abschnitt zuklappen' }],
  ['.copy-to-clipboard, .copy-to-clipboard > button', {
    'Copy cURL command to clipboard': 'cURL-Befehl in die Zwischenablage kopieren',
    'Copy code to clipboard': 'Code in die Zwischenablage kopieren',
    'Copy path to clipboard': 'Pfad in die Zwischenablage kopieren',
  }],
  ['select.content-type', { 'Media Type': 'Medientyp', 'Request content type': 'Medientyp der Anfrage' }],
];

function translation(value, labels) {
  const original = value.trim();
  const pair = Object.entries(labels).find(([en, de]) => original === en || original === de);
  return pair ? value.replace(original, t(pair[1], pair[0])) : value;
}

export function localizeSwagger(explorer) {
  const options = { subtree: true, childList: true, characterData: true, attributes: true,
    attributeFilter: ['aria-label', 'title'] };
  const observer = new MutationObserver(render);

  function render() {
    // Disconnect while writing to avoid observing our own changes. Swagger keeps
    // its current expanded operations, inputs, results and session in place.
    observer.disconnect();
    explorer.lang = t('de', 'en');
    for (const [selector, labels] of controls) {
      for (const element of explorer.querySelectorAll(selector)) {
        for (const node of element.childNodes) {
          if (node.nodeType !== Node.TEXT_NODE) continue;
          const value = translation(node.data, labels);
          if (value !== node.data) node.data = value;
        }
      }
    }
    for (const [selector, labels] of attributes) {
      for (const element of explorer.querySelectorAll(selector)) {
        for (const name of options.attributeFilter) {
          const value = element.getAttribute(name);
          if (value === null) continue;
          const localized = translation(value, labels);
          if (localized !== value) element.setAttribute(name, localized);
        }
      }
    }
    observer.observe(explorer, options);
  }

  onLanguageChange(render);
  render();
}
