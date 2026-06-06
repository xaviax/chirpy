# Chirpy

A JSON REST API server built in Go, backed by PostgreSQL. Users can register, log in, and post short messages called chirps (140 character limit). Supports JWT authentication, refresh tokens, and a premium tier called Chirpy Red managed via webhook.

## Requirements

- Go 1.25+
- PostgreSQL
- [goose](https://github.com/pressly/goose) for running migrations
- [sqlc](https://sqlc.dev) if regenerating database code

## Setup

1. Create a PostgreSQL database named `chirpy`.

2. Run the migrations:

```
goose -dir sql/schema postgres "your-db-url" up
```

3. Create a `.env` file in the project root:

```
DB_URL="postgres://user:password@localhost:5432/chirpy?sslmode=disable"
PLATFORM="dev"
JWT_SECRET="your-secret"
POLKA_KEY="your-polka-api-key"
```

Setting `PLATFORM=dev` enables the `POST /admin/reset` endpoint, which deletes all users and is intended for development only.

## Running

```
go build -o chirpy && ./chirpy
```

The server listens on port `8080`.

## API

### Users

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/users` | Create a user |
| PUT | `/api/users` | Update email and password (JWT required) |
| POST | `/api/login` | Log in, returns JWT and refresh token |
| POST | `/api/refresh` | Issue a new JWT from a refresh token |
| POST | `/api/revoke` | Revoke a refresh token |

### Chirps

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/chirps` | Create a chirp (JWT required) |
| GET | `/api/chirps` | Get all chirps |
| GET | `/api/chirps/{chirpID}` | Get a chirp by ID |
| DELETE | `/api/chirps/{chirpID}` | Delete a chirp (JWT required, must be author) |

Query parameters for `GET /api/chirps`:
- `author_id` — filter by user UUID
- `sort` — `asc` (default) or `desc`

### Webhooks

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/polka/webhooks` | Upgrade a user to Chirpy Red (API key required) |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/metrics` | View file server hit count |
| POST | `/admin/reset` | Delete all users (dev only) |

### Health

```
GET /api/healthz
```
