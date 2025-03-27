from logging.config import fileConfig
from sqlalchemy import create_engine
from sqlalchemy import pool
from alembic import context

# Import your models
from main import Base

DATABASE_URL = "postgresql+psycopg2://anotaton:bea25sof1v4l3@localhost:5432/dataton"
engine = create_engine(DATABASE_URL)

# Set the target metadata
target_metadata = Base.metadata

# Configure Alembic
config = context.config
fileConfig(config.config_file_name)

def run_migrations_offline():
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = engine
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
