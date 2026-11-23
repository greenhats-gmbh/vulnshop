# VulnShop

Minimal Flask shop backend with a native helper for file processing.

## Layout
- `app/` — Flask app (auth, users, reports, admin, payments, crypto)
- `native/` — C helper for uploaded-file processing

## Run
```
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export TOKEN_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
# Set GOOGLE_CLIENT_ID and PAYPROVIDER_TOKEN to enable their integrations.
python -m app.main
make -C native
```
