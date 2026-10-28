// Shared "script variables" rows for the run-script form and the schedule form.
// Expects #varTableBody (with data-max), #varAddBtn, #varMaxHint and #varCountHidden on the page.

let varCount = 0;

function maxScriptVars() {
    return parseInt(document.getElementById('varTableBody').dataset.max, 10) || 10;
}

function updateHint() {
    const max = maxScriptVars();
    document.getElementById('varMaxHint').textContent = `${varCount} / ${max}`;
    document.getElementById('varAddBtn').style.display = varCount >= max ? 'none' : 'flex';
    document.getElementById('varCountHidden').value = varCount;
}

function addVariable() {
    if (varCount >= maxScriptVars()) return;
    varCount++;
    const tbody = document.getElementById('varTableBody');
    const row = document.createElement('div');
    row.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;';
    row.innerHTML = `
        <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 600; width: 20px; text-align: center;">${varCount}</span>
        <input type="text" name="variable${varCount}" data-field="value" placeholder="var" style="flex: 1; padding: 0.45rem 0.6rem; font-size: 0.875rem; border: 1px solid var(--border); border-radius: 6px; box-sizing: border-box;">
        <button type="button" onclick="removeVariable(this)" style="background: none; border: none; cursor: pointer; color: var(--text-muted);">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
    `;
    tbody.appendChild(row);
    updateHint();
}

function removeVariable(btn) {
    btn.closest('div').remove();
    rebuildNames();
}

function rebuildNames() {
    const rows = document.querySelectorAll('#varTableBody > div');
    rows.forEach((row, i) => {
        row.querySelector('span').textContent = i + 1;
        row.querySelector('input[data-field="value"]').name = `variable${i + 1}`;
    });
    varCount = rows.length;
    updateHint();
}
