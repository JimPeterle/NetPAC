ROLE_LEVELS = {"viewer": 1, "operator": 2, "admin": 3}
ROLE_LABELS = {"admin": "Admin", "operator": "Operator", "viewer": "Viewer"}
PROTECTED_ADMIN = "admin"
ROLE_DENIED_MESSAGES = {
    "admin": "Only an admin can do this",
    "operator": "Your role (Viewer) can only view NetPAC — ask an admin for the Operator role",
}


def effective_role(username, role):
    """Returns the role a user really has: 'admin' always is Admin, unknown roles become Viewer."""

    if username == PROTECTED_ADMIN:
        return "admin"
    return role if role in ROLE_LEVELS else "viewer"


def role_at_least(have, need):
    """True if the role 'have' is at least the role 'need'; unknown roles count as no role."""

    return ROLE_LEVELS.get(have, 0) >= ROLE_LEVELS[need]
