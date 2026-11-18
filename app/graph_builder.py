"""Builds the graph of an Ansible playbook by reading its YAML files; nothing is executed."""

import os
import re


MAX_FILE_BYTES = 2 * 1024 * 1024

MAX_NODES = 1500

MAX_DEPTH = 15

MAX_LABEL_LENGTH = 60

TASK_KEYWORDS = {
    "action", "any_errors_fatal", "args", "async", "become", "become_exe", "become_flags", "become_method",
    "become_user", "changed_when", "check_mode", "collections", "connection", "debugger", "delay", "delegate_facts",
    "delegate_to", "diff", "environment", "failed_when", "ignore_errors", "ignore_unreachable", "listen",
    "local_action", "loop", "loop_control", "module_defaults", "name", "no_log", "notify", "poll", "port",
    "register", "remote_user", "retries", "run_once", "tags", "throttle", "timeout", "until", "vars", "when",
}

# Kind of node: (fill colour, text colour)
NODE_STYLES = {
    "playbook": ("#18181b", "#ffffff"),
    "play": ("#2463eb", "#ffffff"),
    "role": ("#7c3aed", "#ffffff"),
    "section": ("#52525b", "#ffffff"),
    "block": ("#0f766e", "#ffffff"),
    "include": ("#b45309", "#ffffff"),
    "task": ("#ffffff", "#18181b"),
    "unresolved": ("#dc2626", "#ffffff"),
}


class GraphError(Exception):
    """Raised when a playbook can't be turned into a graph."""


class BadFileError(GraphError):
    """Raised when a file can't be read; an included file is then only marked in the graph."""


def import_yaml():
    """Returns the yaml module; imported here so NetPAC still starts without it."""

    try:
        import yaml
    except ImportError as e:
        raise GraphError("PyYAML is not installed — install it with: sudo apt install python3-yaml") from e
    return yaml


def make_loader(yaml):
    """Returns a safe YAML loader that also accepts Ansible tags such as !vault and !unsafe."""

    class PlaybookLoader(yaml.SafeLoader):
        """SafeLoader with Ansible's custom tags."""

    def tagged_value(loader, suffix, node):
        """Reads a value with a custom tag; vault contents are not kept."""

        if isinstance(node, yaml.ScalarNode):
            return "[vault]" if suffix == "vault" else loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_mapping(node, deep=True)

    PlaybookLoader.add_multi_constructor("!", tagged_value)
    return PlaybookLoader


def plain(value):
    """Returns a simple value as text; nested YAML is not expanded, it can be huge through aliases."""

    return str(value) if isinstance(value, (str, int, float)) else "…"


def short_text(text):
    """Returns text on one line, shortened for a graph node."""

    text = " ".join(plain(text).split())
    return text if len(text) <= MAX_LABEL_LENGTH else text[:MAX_LABEL_LENGTH - 1] + "…"


def task_module(task):
    """Returns the module a task calls, as written in the playbook."""

    for key in task:
        if str(key) not in TASK_KEYWORDS and not str(key).startswith("with_"):
            return str(key)
    action = task.get("action") or task.get("local_action")
    if isinstance(action, dict):
        return plain(action.get("module", ""))
    return (plain(action).split() or [""])[0] if action else ""


def condition_note(task):
    """Returns the 'when' condition of a task for the graph."""

    when = task.get("when")
    if when in (None, ""):
        return ""
    return "when: " + (" and ".join(plain(item) for item in when[:10]) if isinstance(when, list) else plain(when))


def module_param(task, module, key):
    """Returns a parameter of an include: 'module: value', 'module: {key: value}', 'key=value' or args."""

    value = task.get(module)
    args = task.get("args")
    if isinstance(value, dict) and value.get(key):
        return plain(value[key])
    if isinstance(args, dict) and args.get(key):
        return plain(args[key])
    if isinstance(value, str) and value.strip():
        match = re.search(rf"(?:^|\s){key}=(\S+)", value)
        if match:
            return match.group(1)
        if "{{" in value:
            return value.strip()
        first = value.split()[0]
        return first if "=" not in first else None
    return None


class GraphBuilder:
    """Reads a playbook with its roles and includes into a tree of nodes."""

    def __init__(self, root):
        """Only files inside the root folder are read."""

        self.root = os.path.realpath(root)
        self.nodes = 0
        self.unresolved = 0
        self.yaml = import_yaml()
        self.loader = make_loader(self.yaml)

    def node(self, kind, label, children=None, note=""):
        """Creates a node of the graph."""

        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise GraphError(f"The playbook is too large for a graph (more than {MAX_NODES} elements)")
        return {"kind": kind, "label": short_text(label), "note": short_text(note), "children": children or []}

    def unresolved_node(self, label, note):
        """Creates a node for something that can't be followed without running the playbook."""

        self.unresolved += 1
        return self.node("unresolved", label, note=note)

    def is_inside_root(self, path):
        """True if a path stays inside the root folder (symlinks resolved)."""

        real = os.path.realpath(path)
        return real == self.root or real.startswith(self.root + os.sep)

    def find_file(self, name, folders):
        """Returns the real path of a file in the first folder that has it, inside the root only."""

        for folder in folders:
            if folder:
                candidate = os.path.realpath(os.path.join(folder, name))
                if self.is_inside_root(candidate) and os.path.isfile(candidate):
                    return candidate
        return None

    def load(self, path):
        """Reads a YAML file."""

        name = os.path.relpath(path, self.root)
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                raise BadFileError(f"{name} is too large")
            with open(path, encoding="utf-8", errors="replace") as f:
                return self.yaml.load(f, Loader=self.loader)  # nosec B506 # PlaybookLoader extends yaml.SafeLoader
        except self.yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            raise BadFileError(f"{name} is not valid YAML" + (f" (line {mark.line + 1})" if mark else "")) from e
        except (OSError, RecursionError, ValueError) as e:
            raise BadFileError(f"{name} can't be read") from e

    def read_playbook(self, path, stack, depth):
        """Returns the plays and imported playbooks of a playbook file."""

        data = self.load(path)
        if not isinstance(data, list):
            raise BadFileError(f"{os.path.relpath(path, self.root)} is not a playbook")
        nodes = []
        for item in data:
            if not isinstance(item, dict):
                continue
            module = next((key for key in item if str(key).rsplit(".", 1)[-1] == "import_playbook"), None)
            if module is not None:
                nodes.append(self.imported_playbook(plain(item[module]), path, stack, depth))
            elif "hosts" in item:
                nodes.append(self.play(item, path, stack, depth))
        return nodes

    def imported_playbook(self, name, path, stack, depth):
        """Follows an import_playbook."""

        title = f"import_playbook: {name}"
        if "{{" in name:
            return self.unresolved_node(title, "resolved at run time")
        target = self.find_file(name, [os.path.dirname(path)])
        if target is None:
            return self.unresolved_node(title, "file not found")
        if target in stack or depth >= MAX_DEPTH:
            return self.unresolved_node(title, "imports itself or is nested too deeply")
        try:
            return self.node("playbook", title, self.read_playbook(target, stack | {target}, depth + 1))
        except BadFileError as e:
            return self.unresolved_node(title, str(e))

    def play(self, play, path, stack, depth):
        """Returns a play in the order Ansible runs it: pre_tasks, roles, tasks, post_tasks."""

        folder = os.path.dirname(path)
        context = {"playbook_dir": folder, "file_dir": folder, "role_dir": None}
        children = []
        if play.get("pre_tasks"):
            children.append(self.node("section", "pre_tasks", self.tasks(play["pre_tasks"], context, stack, depth)))
        roles = play.get("roles")
        for entry in roles if isinstance(roles, list) else []:
            name = entry.get("role") or entry.get("name") if isinstance(entry, dict) else entry
            if name:
                note = condition_note(entry) if isinstance(entry, dict) else ""
                children.append(self.role(plain(name), context, stack, depth, note=note))
        children.extend(self.tasks(play.get("tasks"), context, stack, depth))
        if play.get("post_tasks"):
            children.append(self.node("section", "post_tasks", self.tasks(play["post_tasks"], context, stack, depth)))
        hosts = play.get("hosts")
        hosts = ", ".join(plain(host) for host in hosts[:10]) if isinstance(hosts, list) else plain(hosts)
        return self.node("play", play.get("name") or f"Play: {hosts}", children, note=f"hosts: {hosts}")

    def tasks(self, items, context, stack, depth):
        """Returns the nodes of a task list."""

        if not isinstance(items, list):
            return []
        if depth >= MAX_DEPTH:
            return [self.unresolved_node("…", "nested too deeply")]
        return [self.task(item, context, stack, depth) for item in items if isinstance(item, dict)]

    def task(self, task, context, stack, depth):
        """Returns a task, a block, or the content of an include."""

        note = condition_note(task)
        if "block" in task:
            children = self.tasks(task.get("block"), context, stack, depth + 1)
            for section in ("rescue", "always"):
                if task.get(section):
                    children.append(self.node("section", section, self.tasks(task[section], context, stack, depth + 1)))
            return self.node("block", task.get("name") or "block", children, note=note)

        module = task_module(task)
        short = module.rsplit(".", 1)[-1]
        if short in ("include_tasks", "import_tasks"):
            return self.included_tasks(task, module, short, context, stack, depth)
        if short in ("include_role", "import_role"):
            name = module_param(task, module, "name")
            if not name:
                return self.unresolved_node(short, "no role name")
            return self.role(name, context, stack, depth, module_param(task, module, "tasks_from"), note)
        return self.node("task", task.get("name") or short or "task", note=note)

    def included_tasks(self, task, module, short, context, stack, depth):
        """Follows an include_tasks or import_tasks."""

        name = module_param(task, module, "file")
        title = f"{short}: {name}"
        if not name:
            return self.unresolved_node(short, "no file name")
        if "{{" in name:
            return self.unresolved_node(title, "resolved at run time")
        role_tasks = os.path.join(context["role_dir"], "tasks") if context["role_dir"] else None
        target = self.find_file(name, [context["file_dir"], role_tasks, context["playbook_dir"]])
        if target is None:
            return self.unresolved_node(title, "file not found")
        if target in stack:
            return self.unresolved_node(title, "includes itself")
        try:
            data = self.load(target)
        except BadFileError as e:
            return self.unresolved_node(title, str(e))
        inner = {**context, "file_dir": os.path.dirname(target)}
        return self.node("include", task.get("name") or title,
                         self.tasks(data, inner, stack | {target}, depth + 1), note=condition_note(task))

    def find_role(self, name, context):
        """Returns the folder of a role next to the playbook, in the root or next to the calling role."""

        folders = [os.path.join(context["playbook_dir"], "roles"), os.path.join(self.root, "roles"), context["playbook_dir"]]
        if context["role_dir"]:
            folders.insert(0, os.path.dirname(context["role_dir"]))
        for folder in folders:
            candidate = os.path.realpath(os.path.join(folder, name))
            if self.is_inside_root(candidate) and os.path.isdir(candidate):
                return candidate
        return None

    def role(self, name, context, stack, depth, tasks_from=None, note=""):
        """Returns a role with its dependencies and tasks."""

        title = f"Role: {name}"
        if "{{" in name:
            return self.unresolved_node(title, "resolved at run time")
        folder = self.find_role(name, context)
        if folder is None:
            if name.count(".") >= 2:
                return self.node("role", title, note="from a collection")
            return self.unresolved_node(title, "role not found")
        key = f"role:{folder}:{tasks_from or 'main'}"
        if key in stack or depth >= MAX_DEPTH:
            return self.unresolved_node(title, "uses itself or is nested too deeply")

        stack = stack | {key}
        inner = {**context, "role_dir": folder, "file_dir": os.path.join(folder, "tasks")}
        children = []
        try:
            meta = self.find_file("main.yml", [os.path.join(folder, "meta")]) or self.find_file("main.yaml", [os.path.join(folder, "meta")])
            dependencies = (self.load(meta) or {}) if meta else {}
            for entry in dependencies.get("dependencies") or [] if isinstance(dependencies, dict) else []:
                dependency = entry.get("role") or entry.get("name") if isinstance(entry, dict) else entry
                if dependency:
                    children.append(self.role(plain(dependency), inner, stack, depth + 1))

            base = tasks_from or "main"
            tasks_dir = os.path.join(folder, "tasks")
            names = [base] if base.endswith((".yml", ".yaml")) else [f"{base}.yml", f"{base}.yaml", base]
            tasks_file = next((path for path in (self.find_file(n, [tasks_dir]) for n in names) if path), None)
            if tasks_file:
                children.extend(self.tasks(self.load(tasks_file), inner, stack | {tasks_file}, depth + 1))
            elif tasks_from:
                children.append(self.unresolved_node(f"tasks_from: {tasks_from}", "file not found"))
        except BadFileError as e:
            children.append(self.unresolved_node(title, str(e)))
        return self.node("role", title, children, note=note)


def build_playbook_graph(path, root):
    """Returns (tree of nodes, number of elements that can't be followed) for a playbook."""

    builder = GraphBuilder(root)
    real = os.path.realpath(path)
    if not builder.is_inside_root(real):
        raise GraphError("The playbook is outside the playbook folder")
    plays = builder.read_playbook(real, frozenset({real}), 0)
    if not plays:
        raise GraphError(f"{os.path.basename(path)} contains no plays")
    return builder.node("playbook", os.path.basename(path), plays), builder.unresolved


def dot_text(text):
    """Escapes text for a quoted Graphviz string."""

    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text))
    return text.replace("\\", "\\\\").replace('"', '\\"')


def render_dot(root):
    """Returns the Graphviz source of a tree of nodes."""

    lines = [
        "digraph playbook {",
        '  graph [rankdir=LR, bgcolor="transparent", nodesep=0.25, ranksep=0.7];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica,Arial,sans-serif", fontsize=11, margin="0.14,0.08", color="#8b8b8b"];',
        '  edge [color="#8b8b8b", fontcolor="#8b8b8b", fontname="Helvetica,Arial,sans-serif", fontsize=9, arrowsize=0.7];',
    ]
    counter = [0]

    def add(node):
        """Writes a node with its children and returns its id."""

        counter[0] += 1
        node_id = f"n{counter[0]}"
        fill, font = NODE_STYLES[node["kind"]]
        label = dot_text(node["label"]) + (f"\\n{dot_text(node['note'])}" if node["note"] else "")
        style = ', style="rounded,filled,dashed"' if node["kind"] == "unresolved" else ""
        lines.append(f'  {node_id} [label="{label}", fillcolor="{fill}", fontcolor="{font}"{style}];')
        for position, child in enumerate(node["children"], 1):
            child_id = add(child)
            lines.append(f'  {node_id} -> {child_id} [label="{position}"];')
        return node_id

    add(root)
    lines.append("}")
    return "\n".join(lines) + "\n"


def build_playbook_dot(path, root):
    """Returns (Graphviz source, number of elements that can't be followed) for a playbook."""

    tree, unresolved = build_playbook_graph(path, root)
    return render_dot(tree), unresolved
