"""Let the panel run on MariaDB 10.3 (the AppStream default on EL8).

Django 4.2 refuses to connect to MariaDB older than 10.4 although the MySQL
backend still works with 10.3 (Django 4.1 supported it; 4.2 only dropped the
promise). Many CyberPanel hosts on CentOS/Alma/Rocky 8 run 10.3 and upgrading
the database server underneath every hosted site is a separate, deliberate step.
Lower the floor to 10.3 for MariaDB only; MySQL and newer MariaDB are unaffected.
"""


def apply():
    try:
        import django
        from django.db.backends.mysql import features
        from django.utils.functional import cached_property
    except Exception:
        return False
    if django.VERSION[:2] != (4, 2):
        return False
    original = features.DatabaseFeatures.__dict__.get('minimum_database_version')
    if original is None or getattr(original, '_cyberpanel_compat', False):
        return False

    def minimum_database_version(self):
        if self.connection.mysql_is_mariadb:
            return (10, 3)
        return original.func(self) if hasattr(original, 'func') else (8,)

    minimum_database_version._cyberpanel_compat = True
    prop = cached_property(minimum_database_version)
    prop.__set_name__(features.DatabaseFeatures, 'minimum_database_version')
    prop._cyberpanel_compat = True
    features.DatabaseFeatures.minimum_database_version = prop
    return True
