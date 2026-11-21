"""Generate ephemeral CI-only configuration without printing credentials."""
import secrets
from pathlib import Path
password = secrets.token_hex(24)
token = secrets.token_hex(32)
Path('.env').write_text(f'POSTGRES_PASSWORD={password}\nDATABASE_URL=postgresql+psycopg://fuzzcore:{password}@db:5432/fuzzcore\nFUZZCORE_TOKEN={token}\n')
