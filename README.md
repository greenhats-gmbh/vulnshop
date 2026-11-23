# VulnShop

Minimal Flask shop backend with a native helper for file processing.

## Layout
- `app/` — Flask app (auth, users, reports, admin, payments, crypto)
- `native/` — C helper for uploaded-file processing

## Run
```
pip install -r requirements.txt
python -m app.main
make -C native
```
