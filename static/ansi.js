const ANSI_SGR_RE = /\x1b\[([0-9;]*)m/g;
const ANSI_OTHER_RE = /\x1b\[[0-9;?]*[A-Za-z]/g;

function renderAnsi(element, text) {
    const fragment = document.createDocumentFragment();
    let fg = null;
    let bold = false;
    let last = 0;

    function append(chunk) {
        chunk = chunk.replace(ANSI_OTHER_RE, '');
        if (!chunk) return;
        if (!fg && !bold) {
            fragment.appendChild(document.createTextNode(chunk));
            return;
        }
        const span = document.createElement('span');
        if (fg) span.classList.add(`ansi-${fg}`);
        if (bold) span.classList.add('ansi-bold');
        span.textContent = chunk;
        fragment.appendChild(span);
    }

    for (const match of text.matchAll(ANSI_SGR_RE)) {
        append(text.slice(last, match.index));
        last = match.index + match[0].length;

        const codes = match[1] === '' ? [0] : match[1].split(';').map(Number);
        for (const code of codes) {
            if (code === 0) { fg = null; bold = false; }
            else if (code === 1) bold = true;
            else if (code === 22) bold = false;
            else if (code === 39) fg = null;
            else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) fg = code;
        }
    }
    append(text.slice(last));

    element.replaceChildren(fragment);
}
