const ANSI_SGR_RE = /\x1b\[([0-9;]*)m/g;
const ANSI_OTHER_RE = /\x1b\[[0-9;?]*[A-Za-z]/g;
const ANSI_INCOMPLETE_RE = /\x1b(\[[0-9;?]*)?$/;

function createAnsiRenderer(element) {
    let fg = null;
    let bold = false;
    let pending = '';

    function addText(fragment, chunk) {
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

    function append(text) {
        text = pending + text;
        const incomplete = text.match(ANSI_INCOMPLETE_RE);
        pending = incomplete ? incomplete[0] : '';
        if (pending) text = text.slice(0, -pending.length);

        const fragment = document.createDocumentFragment();
        let last = 0;
        for (const match of text.matchAll(ANSI_SGR_RE)) {
            addText(fragment, text.slice(last, match.index));
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
        addText(fragment, text.slice(last));
        element.appendChild(fragment);
    }

    function reset() {
        fg = null;
        bold = false;
        pending = '';
        element.replaceChildren();
    }

    return { append, reset };
}

function renderAnsi(element, text) {
    const renderer = createAnsiRenderer(element);
    renderer.reset();
    renderer.append(text);
    return renderer;
}
