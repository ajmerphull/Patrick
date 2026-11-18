const jobSelect = document.querySelector('#job'),
  form = document.querySelector('#job-form'),
  fields = document.querySelector('#fields');
const description = document.querySelector('#description'),
  statusNode = document.querySelector('#status'),
  output = document.querySelector('#output');
const dialog = document.querySelector('#consent-dialog');

let jobs = [];

function addField(field) {
  const wrap = document.createElement('div');
  if (field.show_if) wrap.dataset.showIf = field.show_if;
  if (field.hide_if) wrap.dataset.hideIf = field.hide_if;
  if (field.type === 'checkbox') {
    wrap.className = 'check';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.id = field.name;
    input.name = field.name;
    const label = document.createElement('label');
    label.htmlFor = field.name;
    label.textContent = field.label + (field.purpose ? ' (opt-in)' : '');
    wrap.append(input, label);
    if (field.description) {
      const hint = document.createElement('small');
      hint.className = 'hint';
      hint.textContent = field.description;
      label.append(hint);
    }
  } else if (field.type === 'php-version') {
    const label = document.createElement('label');
    label.htmlFor = field.name;
    label.textContent = field.label;
    const input = document.createElement('input');
    input.type = 'text';
    input.id = field.name;
    input.name = field.name;
    input.setAttribute('list', 'php-version-options');
    input.placeholder = '8.2 or all';
    input.required = Boolean(field.required);
    input.value = field.default || 'all';
    const options = document.createElement('datalist');
    options.id = 'php-version-options';
    for (const version of field.options || ['all']) {
      const option = document.createElement('option');
      option.value = version === 'all' ? 'all' : version;
      options.append(option);
    }
    wrap.append(label, input, options);
    if (field.description) {
      const hint = document.createElement('small');
      hint.className = 'hint';
      hint.textContent = field.description;
      wrap.append(hint);
    }
  } else {
    const label = document.createElement('label');
    label.htmlFor = field.name;
    label.textContent = field.label;
    const input = document.createElement('input');
    input.type = 'text';
    input.id = field.name;
    input.name = field.name;
    input.placeholder = field.placeholder || '';
    input.required = Boolean(field.required);
    wrap.append(label, input);
  }
  fields.append(wrap);
}

function refreshVisibility() {
  for (const wrap of fields.children) {
    const show = wrap.dataset.showIf;
    const hide = wrap.dataset.hideIf;
    const shown =
      (!show ||
        Boolean(
          document.querySelector('#' + CSS.escape(show))?.checked ||
            document.querySelector('#' + CSS.escape(show))?.value.trim()
        )) &&
      (!hide || !document.querySelector('#' + CSS.escape(hide))?.checked);
    wrap.hidden = !shown;
    if (!shown) {
      const input = wrap.querySelector('input');
      if (input?.type === 'checkbox') input.checked = false;
      else if (input) input.value = '';
    }
  }
}

function refreshProfileIndicator() {
  const job = jobs.find(item => item.id === jobSelect.value);
  const indicator = document.querySelector('#profile-indicator');
  if (!job || !['definitions', 'list-definitions'].includes(job.id)) {
    indicator.textContent = '';
    return;
  }
  const selected = document.querySelector('#php_version')?.value || 'all';
  indicator.textContent =
    'Definition-list coverage: ' +
    (selected === 'all' ? 'all PHP branches' : 'PHP ' + selected) +
    '; PHP core prioritized, extensions best-effort (not all extensions are covered).';
}

function renderJob() {
  const job = jobs.find(item => item.id === jobSelect.value);
  if (!job) return;
  description.textContent = job.description;
  fields.replaceChildren();
  job.fields.forEach(addField);
  refreshVisibility();
  refreshProfileIndicator();
}

function readInputs() {
  const result = {};
  for (const field of jobs.find(item => item.id === jobSelect.value).fields) {
    const input = document.querySelector('#' + CSS.escape(field.name));
    if (field.type === 'checkbox') result[field.name] = input.checked;
    else if (input.value.trim()) result[field.name] = input.value.trim();
  }
  return result;
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const body = await response.json();
  return { response, body };
}

async function confirmPurposes(detail) {
  const required = detail.consent_required;
  document.querySelector('#consent-copy').textContent =
    'This job needs the following network access. Choose session-only access or save permission by purpose.';
  const list = document.querySelector('#purposes');
  list.replaceChildren();
  for (const purpose of required) {
    const item = document.createElement('div');
    item.className = 'purpose';
    const title = document.createElement('strong');
    title.textContent = purpose.replaceAll('_', ' ');
    const text = document.createElement('p');
    text.textContent = detail.descriptions[purpose];
    item.append(title, text);
    list.append(item);
  }
  dialog.showModal();
  return new Promise(resolve =>
    dialog.addEventListener(
      'close',
      () =>
        resolve(
          dialog.returnValue === 'session' || dialog.returnValue === 'always'
            ? {
                confirmed_purposes: required,
                remember_consent: dialog.returnValue === 'always',
              }
            : null
        ),
      { once: true }
    )
  );
}

async function launch(extra = {}) {
  const payload = { job: jobSelect.value, inputs: readInputs(), ...extra };
  const { response, body } = await request('/api/jobs', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (response.status === 428) {
    const consent = await confirmPurposes(body.detail);
    if (!consent) {
      statusNode.textContent = 'Cancelled; no network request was made.';
      return;
    }
    return launch(consent);
  }
  if (!response.ok) {
    statusNode.textContent = body.detail || 'Could not start job.';
    return;
  }
  statusNode.textContent = 'Queued';
  output.textContent = 'Job queued…';
  poll();
}

async function poll() {
  const { body } = await request('/api/jobs/current');
  const job = body.job;
  if (!job) return;
  statusNode.textContent = job.phase + ' ' + job.status;
  statusNode.className = 'status-' + job.status;
  if (job.status === 'queued' || job.status === 'running') {
    document.querySelector('#run').disabled = true;
    setTimeout(poll, 650);
    return;
  }
  document.querySelector('#run').disabled = false;
  output.textContent =
    job.output || job.error || 'Job completed without output.';
}

async function refreshConsent() {
  try {
    const { body } = await request('/api/consent');
    const names = body.always_allow.map(item => item.replaceAll('_', ' '));
    document.querySelector('#consent-status').textContent = names.length
      ? 'Always allowed: ' + names.join(', ')
      : 'No saved always-allow network permissions.';
  } catch {
    document.querySelector('#consent-status').textContent =
      'Could not read saved consent status.';
  }
}

jobSelect.addEventListener('change', renderJob);
fields.addEventListener('input', () => {
  refreshVisibility();
  refreshProfileIndicator();
});

fields.addEventListener('change', refreshProfileIndicator);
form.addEventListener('submit', event => {
  event.preventDefault();
  launch().catch(error => {
    statusNode.textContent = 'Error';
    output.textContent = String(error);
  });
});

document.querySelector('#revoke').addEventListener('click', async () => {
  if (!confirm('Revoke all saved and this-session network permissions?'))
    return;
  const { response, body } = await request('/api/consent', {
    method: 'DELETE',
  });
  document.querySelector('#consent-status').textContent = response.ok
    ? 'All network permissions revoked.'
    : body.detail || 'Could not revoke permissions.';
});

async function init() {
  const { response, body } = await request('/api/jobs');
  if (!response.ok) throw new Error('Could not load job menu.');
  jobs = body.jobs;
  for (const item of jobs) {
    const option = document.createElement('option');
    option.value = item.id;
    option.textContent = item.name;
    jobSelect.append(option);
  }
  renderJob();
  refreshConsent();
  poll();
}
init().catch(error => {
  statusNode.textContent = 'Error';
  output.textContent = String(error);
});
