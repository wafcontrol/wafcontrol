from django.apps import AppConfig


class DbIndexesConfig(AppConfig):
    """Database indexes for wafinstaller tables, built without blocking writes.

    wafinstaller's own migrations are generated on each server (they are not versioned), so an
    index added there would be a plain CREATE INDEX that locks the attack table against writes
    while it is built. This app ships its migrations in the repository instead, and builds the
    indexes with CREATE INDEX CONCURRENTLY on PostgreSQL.
    """

    name = "wafinstaller.db_indexes"
    label = "wafinstaller_db_indexes"
    default_auto_field = "django.db.models.BigAutoField"
