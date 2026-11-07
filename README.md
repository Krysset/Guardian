# Guardian Account Service

## Requirements

- Go
- Node.js
- pnpm

## Installation

- Run `go mod tidy` in `backend` to install dependencies
- Run `pnpm i` in `frontend` to install dependencies

## Run dev environment

### Backend
- Have a local postgresql db up and running
- Run `cd backend`
- Copy `.env.example` and rename it to `.env`
- Fill in the values in `.env`
- Run `go run .`
