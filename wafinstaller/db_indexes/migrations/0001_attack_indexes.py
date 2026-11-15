from django.db import migrations

from wafinstaller.db_indexes.operations import CreateIndexConcurrently


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction.
    atomic = False

    dependencies = [
        ("wafinstaller", "__first__"),
    ]

    operations = [
        # delete_old_attacks() (timestamp < cutoff) and the attack lists (ORDER BY timestamp DESC).
        CreateIndexConcurrently("wafinstaller", "Attack", "wafc_attack_timestamp_idx", ["timestamp"]),
        # Duplicate check run for every rule hit the parser reads (ip, uri, host, rule_id, ...),
        # and the per-IP statistics.
        CreateIndexConcurrently("wafinstaller", "Attack", "wafc_attack_ip_rule_idx", ["ip", "rule_id"]),
    ]
