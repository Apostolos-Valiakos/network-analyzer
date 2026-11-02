"""Alembic environment. Runs inside a Flask app context, using the app's database."""
from alembic import context
from flask import current_app

target_metadata = current_app.extensions["migrate"].db.metadata


def run_migrations_online():
    engine = current_app.extensions["migrate"].db.engine
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("Offline migrations are not supported.")
run_migrations_online()
