import pytest

from graph_builder import MAX_NODES, GraphError, build_playbook_dot, build_playbook_graph, dot_text


def write(folder, name, text):
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def graph(root, text="", name="site.yml"):
    return build_playbook_graph(write(root, name, text), root)


def labels(node):
    found = [node["label"]]
    for child in node["children"]:
        found += labels(child)
    return found


def test_play_runs_in_ansible_order(tmp_path):
    write(tmp_path, "roles/web/tasks/main.yml", "- name: Role task\n  ansible.builtin.ping:\n")
    tree, unresolved = graph(tmp_path, """
- name: Deploy
  hosts: core
  post_tasks:
    - name: Last
      ansible.builtin.ping:
  tasks:
    - name: Middle
      ansible.builtin.ping:
  roles:
    - web
  pre_tasks:
    - name: First
      ansible.builtin.ping:
""")
    play = tree["children"][0]
    assert unresolved == 0
    assert play["label"] == "Deploy" and play["note"] == "hosts: core"
    assert [c["label"] for c in play["children"]] == ["pre_tasks", "Role: web", "Middle", "post_tasks"]
    assert "Role task" in labels(tree)


def test_role_dependencies_and_tasks_from(tmp_path):
    write(tmp_path, "roles/base/tasks/main.yml", "- name: Base task\n  ping:\n")
    write(tmp_path, "roles/app/meta/main.yml", "dependencies:\n  - role: base\n")
    write(tmp_path, "roles/app/tasks/main.yml", "- name: App task\n  ping:\n")
    write(tmp_path, "roles/app/tasks/extra.yml", "- name: Extra task\n  ping:\n")
    tree, unresolved = graph(tmp_path, """
- hosts: all
  roles:
    - role: app
  tasks:
    - ansible.builtin.include_role:
        name: app
        tasks_from: extra
""")
    found = labels(tree)
    assert unresolved == 0
    assert found.index("Base task") < found.index("App task")
    assert "Extra task" in found


def test_includes_and_blocks(tmp_path):
    write(tmp_path, "tasks/inner.yml", "- name: Inner task\n  ping:\n")
    write(tmp_path, "other.yml", "- name: Other play\n  hosts: all\n")
    tree, unresolved = graph(tmp_path, """
- import_playbook: other.yml
- hosts: all
  tasks:
    - import_tasks: tasks/inner.yml
    - name: Safe
      block:
        - name: Try
          ping:
      rescue:
        - name: Recover
          ping:
      always:
        - name: Cleanup
          ping:
      when: run_it
""")
    found = labels(tree)
    assert unresolved == 0
    for label in ("Other play", "Inner task", "Try", "rescue", "Recover", "always", "Cleanup"):
        assert label in found
    block = tree["children"][1]["children"][1]
    assert block["kind"] == "block" and block["note"] == "when: run_it"


@pytest.mark.parametrize("task, note", [
    ('include_tasks: "{{ file }}"', "resolved at run time"),
    ("include_tasks: missing.yml", "file not found"),
    ("include_role:\n        name: unknown", "role not found"),
])
def test_unresolved_elements_are_marked(tmp_path, task, note):
    tree, unresolved = graph(tmp_path, f"- hosts: all\n  tasks:\n    - {task}\n")
    node = tree["children"][0]["children"][0]
    assert unresolved == 1 and node["kind"] == "unresolved" and node["note"] == note


def test_variable_include_shows_the_expression(tmp_path):
    tree, _ = graph(tmp_path, '- hosts: all\n  tasks:\n    - include_tasks: "{{ file }}"\n')
    assert tree["children"][0]["children"][0]["label"] == "include_tasks: {{ file }}"


def test_yaml_alias_bombs_are_not_expanded(tmp_path):
    aliases = "".join(f"    a{i}: &a{i} [*a{i - 1}, *a{i - 1}, *a{i - 1}, *a{i - 1}]\n" for i in range(1, 40))
    tree, _ = graph(tmp_path, f"- hosts: all\n  vars:\n    a0: &a0 [x]\n{aliases}  tasks:\n    - name: *a39\n      ping:\n      when: *a39\n")
    assert tree["children"][0]["children"][0]["label"] == "…"


def test_collection_role_is_no_problem(tmp_path):
    tree, unresolved = graph(tmp_path, "- hosts: all\n  roles:\n    - cisco.ios.ios_config\n")
    assert unresolved == 0 and tree["children"][0]["children"][0]["note"] == "from a collection"


def test_files_outside_the_root_are_not_read(tmp_path):
    root = tmp_path / "playbooks"
    write(tmp_path, "outside.yml", "- name: Secret task\n  ping:\n")
    tree, unresolved = graph(root, "- hosts: all\n  tasks:\n    - include_tasks: ../outside.yml\n")
    assert unresolved == 1 and "Secret task" not in labels(tree)


def test_include_loops_end(tmp_path):
    write(tmp_path, "a.yml", "- include_tasks: b.yml\n")
    write(tmp_path, "b.yml", "- include_tasks: a.yml\n")
    tree, unresolved = graph(tmp_path, "- hosts: all\n  tasks:\n    - include_tasks: a.yml\n")
    assert unresolved == 1 and tree["kind"] == "playbook"


def test_vault_values_are_accepted_and_not_shown(tmp_path):
    tree, _ = graph(tmp_path, """
- name: Vault
  hosts: all
  vars:
    password: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      613233
  tasks:
    - name: Unsafe
      debug:
        msg: !unsafe "{{ raw }}"
""")
    assert "Unsafe" in labels(tree) and "ANSIBLE_VAULT" not in build_playbook_dot(tmp_path / "site.yml", tmp_path)[0]


def test_python_tags_are_rejected(tmp_path):
    with pytest.raises(GraphError):
        graph(tmp_path, '- hosts: all\n  vars:\n    x: !!python/object/apply:os.system ["id"]\n')


@pytest.mark.parametrize("text", ["- hosts: [unclosed\n", "just: a mapping\n", "- name: Only a task\n  ping:\n", ""])
def test_files_that_are_no_playbook_are_rejected(tmp_path, text):
    with pytest.raises(GraphError):
        graph(tmp_path, text)


def test_very_large_playbooks_are_rejected(tmp_path):
    tasks = "".join(f"    - name: Task {i}\n      ping:\n" for i in range(MAX_NODES + 1))
    with pytest.raises(GraphError):
        graph(tmp_path, f"- hosts: all\n  tasks:\n{tasks}")


def test_labels_are_escaped_for_graphviz(tmp_path):
    assert dot_text('a "b" \\ c\nd') == 'a \\"b\\" \\\\ c d'
    source, _ = build_playbook_dot(write(tmp_path, "site.yml", """
- hosts: all
  tasks:
    - name: 'say "hi"]; n1 -> n2 [label="x'
      ping:
"""), tmp_path)
    assert 'say \\"hi\\"]; n1 -> n2 [label=\\"x' in source
    assert source.startswith("digraph playbook {") and source.rstrip().endswith("}")
