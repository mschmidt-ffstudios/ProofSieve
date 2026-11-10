const preferenceKey = 'proofsieve:language';
const supported = new Set(['de', 'en']);
const listeners = new Set();
const pickers = [...document.querySelectorAll('select[data-language]')];
const originalTitle = document.title;
const englishTitle = document.documentElement.dataset.enTitle;
const textBindings = [...document.querySelectorAll('[data-en]')].map(element => ({
  element, de: element.textContent, en: element.dataset.en,
}));
const attributeBindings = ['aria-label', 'placeholder', 'title'].flatMap(attribute =>
  [...document.querySelectorAll(`[data-en-${attribute}]`)].map(element => ({
    element, attribute, de: element.getAttribute(attribute), en: element.getAttribute(`data-en-${attribute}`),
  })));

function readPreference() {
  try {
    return localStorage.getItem(preferenceKey);
  } catch {
    return null;
  }
}

let language = readPreference() === 'en' ? 'en' : 'de';

export function t(de, en) {
  return language === 'en' ? en : de;
}

export function onLanguageChange(listener) {
  listeners.add(listener);
}

function translatePage() {
  document.documentElement.lang = language;
  if (englishTitle) document.title = t(originalTitle, englishTitle);
  for (const binding of textBindings) {
    binding.element.textContent = binding[language];
  }
  for (const binding of attributeBindings) {
    const value = binding[language];
    if (value === null) binding.element.removeAttribute(binding.attribute);
    else binding.element.setAttribute(binding.attribute, value);
  }
  for (const picker of pickers) picker.value = language;
}

function switchLanguage(next) {
  if (!supported.has(next) || language === next) return;
  language = next;
  translatePage();
  for (const listener of listeners) listener(language);
}

for (const picker of pickers) {
  picker.addEventListener('change', () => {
    switchLanguage(picker.value);
    try {
      localStorage.setItem(preferenceKey, language);
    } catch {
      // The current page can still change language without browser storage.
    }
  });
}

window.addEventListener('storage', event => {
  if (event.key === preferenceKey) switchLanguage(event.newValue === 'en' ? 'en' : 'de');
});

translatePage();
