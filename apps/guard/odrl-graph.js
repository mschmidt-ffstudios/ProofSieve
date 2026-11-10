import { t } from '../shared/i18n.js';

const MAX_DEPTH = 8;
const MAX_NODES = 128;
const PROFILE = 'https://proofsieve.example/profiles/basic/v1';
const FIELD = /^field:[A-Za-z_][A-Za-z0-9_-]*$/;
const GROUPS = {
  and: ['UND', 'AND', 'Alle Zweige müssen zutreffen', 'All branches must match'],
  or: ['ODER', 'OR', 'Mindestens ein Zweig muss zutreffen', 'At least one branch must match'],
  xone: ['GENAU EINS', 'EXACTLY ONE', 'Genau ein Zweig muss zutreffen', 'Exactly one branch must match'],
};
const OPERATORS = {
  eq: ['=', 'ist gleich', 'equals'],
  neq: ['≠', 'ist ungleich', 'does not equal'],
  gt: ['>', 'ist größer als', 'is greater than'],
  gteq: ['≥', 'ist mindestens', 'is at least'],
  lt: ['<', 'ist kleiner als', 'is less than'],
  lteq: ['≤', 'ist höchstens', 'is at most'],
};

function fail(de, en) {
  throw new Error(t(de, en));
}

function element(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = text;
  return result;
}

function hasKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function groupOf(node) {
  return Object.keys(GROUPS).find(operator => hasKeys(node, [operator]));
}

function isGraphScalar(value) {
  return typeof value === 'string' || typeof value === 'boolean'
    || (Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)));
}

function validateLeaf(node) {
  if (!hasKeys(node, ['leftOperand', 'operator', 'rightOperand'])
      || typeof node.leftOperand !== 'string' || !FIELD.test(node.leftOperand)
      || typeof node.operator !== 'string' || !Object.hasOwn(OPERATORS, node.operator)
      || !isGraphScalar(node.rightOperand)) {
    fail('Der Graph braucht gültige Feldbedingungen mit skalaren Werten im sicheren Zahlenbereich.',
      'The graph needs valid field comparisons with scalar values in the safe numeric range.');
  }
  if (node.operator !== 'eq' && node.operator !== 'neq' && typeof node.rightOperand !== 'number') {
    fail('Größenvergleiche brauchen einen numerischen Sollwert.', 'Ordering comparisons need a numeric value.');
  }
}

function decimalValue(text) {
  const [mantissa, exponent = '0'] = text.toLowerCase().split('e');
  const [integer, fraction = ''] = mantissa.replace(/^-/, '').split('.');
  const digits = (integer + fraction).replace(/^0+/, '');
  if (!digits) return '0';
  const significant = digits.replace(/0+$/, '');
  const power = Number(exponent) - fraction.length + digits.length - significant.length;
  return `${mantissa.startsWith('-') ? '-' : ''}${significant}e${power}`;
}

function checkNumberText(text) {
  const number = Number(text);
  if (!Number.isFinite(number) || decimalValue(text) !== decimalValue(String(number))) {
    fail('Der Regelgraph würde diesen Zahlenwert runden. Der JSON-LD-Text bleibt erhalten.',
      'The rule graph would round this numeric value. The JSON-LD text is preserved.');
  }
}

function checkLosslessJson(text) {
  // JSON.parse has already checked syntax. String tokens include escapes and all
  // delimiters inside strings, so the stack only follows actual containers.
  const objects = [];
  const tokens = /"(?:[^"\\]|\\.)*"|[{}\[\]]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  for (const match of text.matchAll(tokens)) {
    const token = match[0];
    if (token === '{') objects.push(new Set());
    else if (token === '[') objects.push(null);
    else if (token === '}' || token === ']') objects.pop();
    else if (token.startsWith('"') && /^\s*:/.test(text.slice(match.index + token.length))) {
      const key = JSON.parse(token);
      const keys = objects.at(-1);
      if (keys.has(key)) fail('Doppelte JSON-Schlüssel können im Graphen nicht geöffnet werden.',
        'The graph cannot open duplicate JSON keys.');
      keys.add(key);
    } else if (!token.startsWith('"')) checkNumberText(token);
  }
}

function validatePolicy(policy) {
  const permission = Array.isArray(policy?.permission) && policy.permission.length === 1
    ? policy.permission[0] : null;
  const context = policy?.['@context'];
  if (!hasKeys(policy, ['@context', '@type', 'uid', 'profile', 'permission'])
      || !Array.isArray(context) || context.length !== 2 || context[0] !== 'http://www.w3.org/ns/odrl.jsonld'
      || !hasKeys(context[1], ['field']) || context[1].field !== 'https://proofsieve.example/facts/'
      || policy['@type'] !== 'Set' || typeof policy.uid !== 'string' || policy.profile !== PROFILE
      || !hasKeys(permission, ['target', 'action', 'constraint']) || typeof permission.target !== 'string'
      || !['use', 'odrl:use'].includes(permission.action) || !Array.isArray(permission.constraint)
      || !permission.constraint.length) {
    fail('Der Entwurf passt nicht zum Basic-Guard-Profil für den Regelgraphen.',
      'The draft does not match the Basic Guard profile for the policy graph.');
  }

  let count = 0;
  function visit(node, depth) {
    count += 1;
    if (depth > MAX_DEPTH || count > MAX_NODES) {
      fail('Der Regelgraph unterstützt bis zu 8 Ebenen unter der obersten Bedingung und 128 Regelknoten.',
        'The policy graph supports up to 8 levels below a top-level constraint and 128 rule nodes.');
    }
    const operator = groupOf(node);
    if (!operator) {
      validateLeaf(node);
      return;
    }
    if (!Array.isArray(node[operator]) || node[operator].length < 2) {
      fail('Eine Logikgruppe braucht mindestens zwei Zweige.', 'A logical group needs at least two branches.');
    }
    node[operator].forEach(child => visit(child, depth + 1));
  }

  permission.constraint.forEach(node => visit(node, 0));
  return count;
}

function parsePolicy(text) {
  let policy;
  try {
    policy = JSON.parse(text);
  } catch {
    fail('Der Entwurf enthält noch kein gültiges JSON. Bearbeite den Regeltext, um den Graphen anzuzeigen.',
      'The draft does not contain valid JSON yet. Edit the rule text to display its graph.');
  }
  checkLosslessJson(text);
  return { policy, count: validatePolicy(policy) };
}

function groupLabel(operator) {
  const [de, en] = GROUPS[operator];
  return t(de, en);
}

function groupDescription(operator) {
  const [, , de, en] = GROUPS[operator];
  return t(de, en);
}

function childrenOf(node) {
  const operator = groupOf(node);
  return operator ? node[operator] : [];
}

function nodeAt(nodes, path) {
  let node;
  for (const index of path) {
    node = nodes[index];
    nodes = childrenOf(node);
  }
  return node;
}

function childrenAt(nodes, path) {
  return path.length ? childrenOf(nodeAt(nodes, path)) : nodes;
}

function fieldComparison(name, value) {
  return { leftOperand: `field:${name}`, operator: 'eq', rightOperand: value };
}

function newGroup() {
  return { or: [fieldComparison('issuing_country', 'DE'), fieldComparison('issuing_country', 'FR')] };
}

function button(text, action, className) {
  const result = element('button', className, text);
  result.type = 'button';
  result.addEventListener('click', action);
  return result;
}

function controlLabel(caption, input) {
  const label = element('label', '', caption);
  label.append(input);
  return label;
}

function picker(entries, selected) {
  const select = element('select');
  for (const [key, label] of entries) select.add(new Option(label, key));
  select.value = selected;
  return select;
}

export function createOdrlGraph(container, onChange, onPendingChange) {
  let source = '';
  let policy;
  let count;
  let selection = [];
  let readOnly = false;
  let feedback;
  let pending = null;

  function confirmDiscard() {
    return !pending || window.confirm(t('Unübernommene Änderungen an der Bedingung verwerfen?',
      'Discard the unapplied changes to this condition?'));
  }

  function commit(change, path, applyingCondition = false) {
    if (!applyingCondition && !confirmDiscard()) return;
    try {
      const draft = JSON.parse(source);
      change(draft.permission[0].constraint);
      validatePolicy(draft);
      pending = null;
      selection = path;
      onChange(JSON.stringify(draft, null, 2));
    } catch (error) {
      feedback.textContent = error.message;
      feedback.hidden = false;
    }
  }

  function select(path) {
    if (selection.join('.') === path.join('.') || !confirmDiscard()) return;
    const hadPending = Boolean(pending);
    pending = null;
    selection = path;
    draw();
    if (hadPending) onPendingChange();
    container.querySelector('[aria-pressed="true"]')?.focus({ preventScroll: true });
  }

  function tile(path, type, token, primary, secondary) {
    const active = !readOnly && selection.join('.') === path.join('.');
    const node = readOnly
      ? element('div', 'odrl-node')
      : button(undefined, () => select(path), 'odrl-node');
    node.dataset.nodePath = path.join('.');
    node.dataset.kind = type;
    if (!readOnly) node.setAttribute('aria-pressed', String(active));
    const copy = element('span', 'odrl-node-copy');
    copy.append(element(type === 'condition' ? 'code' : 'strong', '', primary));
    if (secondary) copy.append(element('span', 'odrl-node-detail', secondary));
    node.append(element('span', 'odrl-node-token', token), copy);
    return node;
  }

  function tree(nodes, path = []) {
    const branches = element('ul', 'odrl-branches');
    nodes.forEach((node, index) => {
      const nodePath = [...path, index];
      const branch = element('li', 'odrl-branch');
      const group = groupOf(node);
      if (group) {
        branch.append(tile(nodePath, group, groupLabel(group), groupDescription(group),
          t(`${node[group].length} Zweige`, `${node[group].length} branches`)));
        branch.append(tree(node[group], nodePath));
      } else {
        const [symbol] = OPERATORS[node.operator];
        branch.append(tile(nodePath, 'condition', symbol, node.leftOperand.slice(6), JSON.stringify(node.rightOperand)));
      }
      branches.append(branch);
    });
    return branches;
  }

  function removeNode(nodes, parentPath) {
    const parent = childrenAt(nodes, parentPath);
    parent.splice(selection.at(-1), 1);
    if (parentPath.length && parent.length === 1) {
      childrenAt(nodes, parentPath.slice(0, -1))[parentPath.at(-1)] = parent[0];
    }
  }

  function editGroup(inspector, actions, nodes, path, group) {
    if (path.length) {
      const operator = picker(Object.keys(GROUPS).map(key => [key, groupLabel(key)]), group);
      operator.addEventListener('change', () => commit(items => {
        const current = childrenAt(items, path.slice(0, -1));
        current[path.at(-1)] = { [operator.value]: childrenOf(current[path.at(-1)]) };
      }, path));
      inspector.append(controlLabel(t('Logik', 'Logic'), operator));
    }
    const branchCount = childrenAt(nodes, path).length;
    const addCondition = button(t('+ Bedingung', '+ Condition'), () => commit(items => {
      childrenAt(items, path).push(fieldComparison('status', 'active'));
    }, [...path, branchCount]));
    addCondition.disabled = path.length > MAX_DEPTH || count >= MAX_NODES;
    const addGroup = button(t('+ Logikgruppe', '+ Logical group'), () => commit(items => {
      childrenAt(items, path).push(newGroup());
    }, [...path, branchCount]));
    addGroup.disabled = path.length >= MAX_DEPTH || count + 3 > MAX_NODES;
    actions.append(addCondition, addGroup);
  }

  function editLeaf(inspector, actions, node, path) {
    const form = element('form', 'odrl-fields');
    const original = { field: node.leftOperand.slice(6), operator: node.operator, value: JSON.stringify(node.rightOperand) };
    const current = pending ?? original;
    const field = element('input');
    field.value = current.field;
    field.spellcheck = false;
    const operator = picker(Object.entries(OPERATORS).map(([key, [sign, de, en]]) =>
      [key, `${sign} ${t(de, en)}`]), current.operator);
    const value = element('input');
    value.value = current.value;
    value.spellcheck = false;
    const apply = element('button', 'primary', t('Bedingung übernehmen', 'Apply condition'));
    apply.type = 'submit';
    const discard = button(t('Änderung verwerfen', 'Discard changes'), () => {
      pending = null;
      draw();
      onPendingChange();
      container.querySelector('.odrl-fields input')?.focus();
    });
    discard.hidden = !pending;
    const controls = element('div', 'odrl-field-grid');
    controls.append(
      controlLabel(t('Feld', 'Field'), field),
      controlLabel(t('Vergleich', 'Comparison'), operator),
      controlLabel(t('Sollwert (JSON)', 'Expected value (JSON)'), value),
    );
    form.append(controls, apply, discard);
    form.addEventListener('input', () => {
      const edited = { field: field.value, operator: operator.value, value: value.value };
      const hadPending = Boolean(pending);
      pending = Object.keys(original).some(key => edited[key] !== original[key]) ? edited : null;
      discard.hidden = !pending;
      if (hadPending !== Boolean(pending)) onPendingChange();
    });
    form.addEventListener('submit', event => {
      event.preventDefault();
      commit(items => {
        const current = childrenAt(items, path.slice(0, -1));
        let expected;
        try {
          expected = JSON.parse(value.value);
        } catch {
          fail('Gib einen JSON-Sollwert ein, etwa "DE", 18 oder true.',
            'Enter a JSON value, for example "DE", 18 or true.');
        }
        if (typeof expected === 'number') checkNumberText(value.value.trim());
        current[path.at(-1)] = {
          leftOperand: `field:${field.value.trim()}`, operator: operator.value, rightOperand: expected,
        };
      }, path, true);
    });
    inspector.append(form);

    const wrap = button(t('In Logikgruppe verschachteln', 'Nest in a logical group'), () => commit(items => {
      const current = childrenAt(items, path.slice(0, -1));
      const leaf = current[path.at(-1)];
      const other = leaf.leftOperand === 'field:status'
        ? fieldComparison('issuing_country', 'DE') : fieldComparison('status', 'active');
      current[path.at(-1)] = { and: [leaf, other] };
    }, path));
    wrap.disabled = path.length > MAX_DEPTH || count + 2 > MAX_NODES;
    actions.append(wrap);
  }

  function editor(nodes) {
    const path = selection;
    const node = nodeAt(nodes, path);
    const group = groupOf(node);
    const parentPath = path.slice(0, -1);
    const editor = element('div', 'odrl-inspector');
    const title = !path.length ? t('Erlaubnis bearbeiten', 'Edit permission') : group
      ? t('Logikgruppe bearbeiten', 'Edit logical group') : t('Bedingung bearbeiten', 'Edit condition');
    editor.append(element('strong', 'odrl-inspector-title', title));
    const actions = element('div', 'actions odrl-actions');
    if (!path.length || group) editGroup(editor, actions, nodes, path, group);
    else editLeaf(editor, actions, node, path);

    if (path.length && (parentPath.length || nodes.length > 1)) {
      actions.append(button(t('Entfernen', 'Remove'),
        () => commit(items => removeNode(items, parentPath), parentPath), 'odrl-remove'));
    }
    feedback = element('p', 'odrl-error');
    feedback.hidden = true;
    feedback.setAttribute('role', 'status');
    editor.append(actions, feedback);
    return editor;
  }

  function draw() {
    const permission = policy.permission[0];
    const nodes = permission.constraint;
    if (selection.length && !nodeAt(nodes, selection)) selection = [];
    const canvas = element('div', 'odrl-canvas');
    canvas.append(tile([], 'permission', permission.action, t('Nutzung erlauben', 'Allow use'), permission.target));
    if (nodes.length > 1) {
      const top = element('ul', 'odrl-branches');
      const branch = element('li', 'odrl-branch');
      const implicit = element('div', 'odrl-implicit');
      implicit.append(element('strong', '', groupLabel('and')),
        element('span', '', t('Alle Bedingungen der Erlaubnis', 'All permission constraints')));
      branch.append(implicit, tree(nodes));
      top.append(branch);
      canvas.append(top);
    } else {
      canvas.append(tree(nodes));
    }
    const heading = element('div', 'odrl-graph-heading');
    heading.append(element('strong', '', t('ODRL-Regelgraph', 'ODRL policy graph')),
      element('span', '', t(`${count} Regelknoten`, `${count} rule nodes`)));
    container.replaceChildren(heading, canvas);
    if (!readOnly) container.append(editor(nodes));
  }

  function render(policyText, options = {}) {
    if (source !== policyText || readOnly !== (options.readOnly ?? false)) pending = null;
    source = policyText;
    readOnly = options.readOnly ?? false;
    try {
      ({ policy, count } = parsePolicy(source));
      draw();
    } catch (error) {
      const heading = element('div', 'odrl-graph-heading', t('ODRL-Regelgraph', 'ODRL policy graph'));
      container.replaceChildren(heading, element('p', 'odrl-error', error.message));
    }
  }

  container.classList.add('odrl-graph');
  return {
    render,
    hasPendingEdit: () => Boolean(pending),
    resetEdit: () => { pending = null; },
  };
}
