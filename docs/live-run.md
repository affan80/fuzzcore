# Temporary live run in a GitHub Codespace

This runs the existing fixture-only backend stack for a short demo window. It is not a permanent host. The scanner can only reach the bundled isolated lab; there is no user-supplied target.

## Start

1. Create a Codespace from this repository (2-core is enough to try; GitHub Free includes 120 core-hours a month).
2. The devcontainer generates a random `.env` (never committed) and runs `docker compose up -d --build`.
3. Wait for `curl -s http://127.0.0.1:8000/health` to answer.
4. In the Ports tab, set port 8000 to **Public**. The app sends its own bearer token, so a Private port (which needs a GitHub token) will not work from the phone.
5. The API address is `https://<codespace-name>-8000.app.github.dev`. Enter it and the connection token from the Codespace `.env` file (`FUZZCORE_TOKEN`) in the app. Do not paste the token into chat or an issue.

## Restart

Codespaces stop when idle. Start it again from github.com/codespaces. The stack restarts through `postStartCommand`. Check that port 8000 is still Public and that the address in the app is still the same name; if the codespace was recreated, the address changes.

## Stop

Delete the Codespace after the demo. Only the lab fixture is scanned; the token is the only access gate, so treat it as a secret and rotate by deleting `.env` and recreating.

## Limits

Verified claims belong in the PR that used this file. Device behaviour is not verified by this document.
