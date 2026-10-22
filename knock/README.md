# Knock — network port scanner

A web UI and Node.js TCP connect scanner with a live radar view. No dependencies.

## Run
    node server.js
Open http://127.0.0.1:3000

## Options (environment variables)
- `PORT` (default 3000), `HOST` (default 127.0.0.1)
- `ALLOW_PUBLIC=1` lets the server scan public IP addresses. Off by default: only private and loopback targets are allowed.

## Features
Top 100, common, web, 1–1024, all ports or a custom list · live streaming results · banner reading · service names and risk advice · radar map · JSON/CSV export.

## Responsible use
Scan only systems you own or have written permission to test.
