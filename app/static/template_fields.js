const FIELD_TYPE_LABELS = {
    text: 'Text', textarea: 'Text (multiline)', number: 'Number', select: 'Select',
    multiselect: 'Multi-select', boolean: 'Yes / No', password: 'Password'
};

function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
        if (key === 'text') node.textContent = value;
        else if (key === 'style') node.style.cssText = value;
        else if (key in node && typeof value !== 'string') node[key] = value;
        else node.setAttribute(key, value);
    }
    children.forEach(child => node.appendChild(child));
    return node;
}

function addFieldRow(containerId, field = {}) {
    const container = document.getElementById(containerId);
    const typeSelect = el('select', { class: 'form-input', 'data-key': 'field_type' },
        Object.entries(FIELD_TYPE_LABELS).map(([value, label]) => el('option', { value, text: label })));
    typeSelect.value = field.field_type || 'text';

    const options = el('textarea', { class: 'form-input', 'data-key': 'options', rows: '3',
        placeholder: 'Options, one per line', style: 'font-family: inherit; resize: vertical;' });
    options.value = (field.options || []).join('\n');

    const defaultInput = el('input', { type: 'text', class: 'form-input', 'data-key': 'default_value', placeholder: 'Default value' });
    defaultInput.value = field.default_value || '';

    const required = el('input', { type: 'checkbox', 'data-key': 'required', style: 'width: 16px; height: 16px; accent-color: var(--accent);' });
    required.checked = !!field.required;

    const varName = el('input', { type: 'text', class: 'form-input', 'data-key': 'var_name', placeholder: 'variable_name', required: 'required' });
    varName.value = field.var_name || '';
    const label = el('input', { type: 'text', class: 'form-input', 'data-key': 'label', placeholder: 'Label shown in the form' });
    label.value = field.label || '';

    const removeBtn = el('button', { type: 'button', class: 'action-button action-button-secondary', title: 'Remove field', text: '✕' });
    const row = el('div', { class: 'survey-field-row' }, [
        el('div', { class: 'survey-field-grid' }, [varName, label, typeSelect]),
        el('div', { class: 'survey-field-grid' }, [
            defaultInput,
            el('label', { class: 'survey-field-required' }, [required, el('span', { text: 'Required' })]),
            removeBtn
        ]),
        options
    ]);

    function updateType() {
        const type = typeSelect.value;
        options.style.display = (type === 'select' || type === 'multiselect') ? '' : 'none';
        defaultInput.style.visibility = type === 'password' ? 'hidden' : 'visible';
        defaultInput.placeholder = type === 'boolean' ? 'Default: true or false'
            : type === 'multiselect' ? 'Default options, comma separated' : 'Default value';
    }
    typeSelect.addEventListener('change', updateType);
    removeBtn.addEventListener('click', () => row.remove());
    updateType();
    container.appendChild(row);
}

function renderFieldEditor(containerId, fields) {
    document.getElementById(containerId).replaceChildren();
    (fields || []).forEach(field => addFieldRow(containerId, field));
}

function serializeFields(containerId) {
    return JSON.stringify([...document.querySelectorAll(`#${containerId} .survey-field-row`)].map(row => {
        const value = key => row.querySelector(`[data-key="${key}"]`);
        return {
            var_name: value('var_name').value.trim(),
            label: value('label').value.trim(),
            field_type: value('field_type').value,
            required: value('required').checked,
            default_value: value('default_value').value,
            options: value('options').value
        };
    }));
}

function bindFieldEditor(formId, containerId, hiddenId) {
    document.getElementById(formId).addEventListener('submit', () => {
        document.getElementById(hiddenId).value = serializeFields(containerId);
    });
}

function isTruthy(value) {
    return ['true', '1', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function buildLaunchInput(field) {
    const name = `field_${field.var_name}`;
    const required = field.required && !['boolean', 'multiselect'].includes(field.field_type);
    let input;

    if (field.field_type === 'textarea') {
        input = el('textarea', { name, class: 'form-input', rows: '3', style: 'font-family: inherit; resize: vertical;' });
        input.value = field.default_value || '';
    } else if (field.field_type === 'select') {
        input = el('select', { name, class: 'form-input' });
        if (!field.required) input.appendChild(el('option', { value: '', text: '—' }));
        field.options.forEach(option => input.appendChild(el('option', { value: option, text: option })));
        input.value = field.default_value || (field.required ? field.options[0] : '');
    } else if (field.field_type === 'multiselect') {
        const defaults = (field.default_value || '').split(',').map(s => s.trim());
        input = el('div', { class: 'survey-launch-choices' }, field.options.map(option => {
            const box = el('input', { type: 'checkbox', name, value: option, style: 'width: 16px; height: 16px; accent-color: var(--accent);' });
            box.checked = defaults.includes(option);
            return el('label', { class: 'survey-field-required' }, [box, el('span', { text: option })]);
        }));
    } else if (field.field_type === 'boolean') {
        const box = el('input', { type: 'checkbox', name, style: 'width: 16px; height: 16px; accent-color: var(--accent);' });
        box.checked = isTruthy(field.default_value);
        input = el('label', { class: 'survey-field-required' }, [box, el('span', { text: 'Yes' })]);
    } else {
        const type = field.field_type === 'number' ? 'number' : field.field_type === 'password' ? 'password' : 'text';
        input = el('input', { type, name, class: 'form-input' });
        if (type === 'number') input.step = 'any';
        if (type === 'password') input.autocomplete = 'new-password';
        else input.value = field.default_value || '';
    }
    if (required && input.tagName !== 'DIV' && input.tagName !== 'LABEL') input.required = true;

    return el('div', { class: 'form-group', style: 'margin-bottom: 14px;' }, [
        el('label', { class: 'form-label', text: field.label + (field.required ? ' *' : '') }),
        input
    ]);
}

function openLaunchModal(launchUrl, templateName, fields, dryRun) {
    document.getElementById('launchForm').action = launchUrl;
    document.getElementById('launchDryRun').value = dryRun ? 'on' : '';
    document.getElementById('launchModalTitle').textContent = `${dryRun ? 'Dry run' : 'Launch'}: ${templateName}`;
    document.getElementById('launchSubmitBtn').textContent = dryRun ? 'Start dry run' : 'Launch';
    document.getElementById('launchFields').replaceChildren(...fields.map(buildLaunchInput));
    openModalAnimated('launchModal');
}
