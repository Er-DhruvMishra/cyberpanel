try:
    from .mariadb_compat import apply as _apply_mariadb_compat
    _apply_mariadb_compat()
except Exception:  # never block the panel from importing
    pass
