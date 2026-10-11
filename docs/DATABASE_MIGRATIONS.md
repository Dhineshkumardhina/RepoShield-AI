# Database Migrations Guide

RepoShield AI utilizes **Alembic** with SQLAlchemy 2.0 to provide reliable, version-controlled schema migrations for both SQLite (local development) and PostgreSQL (staging/production).

---

## 1. Migration Directory Layout

```
backend/
├── alembic.ini              # Main Alembic configuration
└── alembic/
    ├── env.py               # Migration context script configured to read Settings
    ├── script.py.mako       # Migration template
    └── versions/            # Version-controlled migration revisions
        └── 0001_initial_schema.py
```

---

## 2. Common PowerShell Commands

### Run Pending Migrations
```powershell
python -m alembic -c backend/alembic.ini upgrade head
```

### View Current Migration Version
```powershell
python -m alembic -c backend/alembic.ini current
```

### Create a New Migration
```powershell
# Auto-generate from SQLAlchemy ORM changes
python -m alembic -c backend/alembic.ini revision --autogenerate -m "add_new_column_to_repositories"
```

### Rollback the Last Migration
```powershell
python -m alembic -c backend/alembic.ini downgrade -1
```

---

## 3. Switching to Production PostgreSQL

To switch from SQLite to PostgreSQL:

1. In `.env`, set:
   ```env
   APP_ENV="production"
   DATABASE_URL="postgresql+psycopg://username:password@postgres-host:5432/reposhield_prod"
   ```
2. Run migrations against PostgreSQL:
   ```powershell
   python -m alembic -c backend/alembic.ini upgrade head
   ```
3. The engine automatically enables connection pooling (`pool_pre_ping=True`) and enforces all foreign key constraints.
