from django.db import migrations


class CreateIndexConcurrently(migrations.RunPython):
    """Create an index on another app's model without blocking writes on PostgreSQL.

    Works like AddIndexConcurrently, for a model whose migrations live in another app. Needs a
    non-atomic migration. On other databases a regular CREATE INDEX is used. Idempotent: an index
    left INVALID by an interrupted concurrent build is dropped and built again.
    """

    def __init__(self, app_label, model_name, name, columns):
        self.target = (app_label, model_name)
        self.index_name = name
        self.columns = tuple(columns)
        super().__init__(self._create, self._drop, elidable=False)

    def describe(self):
        return f"Create index {self.index_name} on {self.target[1]} ({', '.join(self.columns)}) concurrently"

    def _table(self, apps):
        return apps.get_model(*self.target)._meta.db_table

    def _create(self, apps, schema_editor):
        conn = schema_editor.connection
        qn = schema_editor.quote_name
        table = self._table(apps)
        cols = ", ".join(qn(c) for c in self.columns)
        if conn.vendor != "postgresql":
            schema_editor.execute(f"CREATE INDEX IF NOT EXISTS {qn(self.index_name)} ON {qn(table)} ({cols})")
            return
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                "WHERE c.relname = %s", [self.index_name])
            row = cursor.fetchone()
        if row and row[0]:
            return
        if row:
            schema_editor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {qn(self.index_name)}")
        schema_editor.execute(f"CREATE INDEX CONCURRENTLY {qn(self.index_name)} ON {qn(table)} ({cols})")

    def _drop(self, apps, schema_editor):
        concurrently = " CONCURRENTLY" if schema_editor.connection.vendor == "postgresql" else ""
        schema_editor.execute(f"DROP INDEX{concurrently} IF EXISTS {schema_editor.quote_name(self.index_name)}")
