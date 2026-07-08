# syntax=docker/dockerfile:1
#
# vapi.Dockerfile — build the vAPI (roottusk/vapi) vulnerable Laravel 8 app
# into the `vapi-www` image used by this demo.
#
# Pinned commit 67152695b0acf13dd424905729080fbc80d5a593 is the one
# openapi.yaml was annotated against. Bumping it without re-checking the
# route shapes risks drift between the app and the compiled policy.
#
# Upstream ships its own Dockerfile (php:7.4-apache + committed vendor/),
# but does not publish an image. This file reproduces that contract with a
# pinned commit so `docker compose up` works on a fresh clone.
#
# Runtime CMD is `php artisan serve` (NOT apache) — the preflight-vapi.sh
# entrypoint assumes the PHP built-in dev server on port 80. Apache is
# installed by the base image but unused at runtime: its default vhost points
# at /var/www/html/, not /var/www/html/vapi/public, so apache2-foreground
# would 404 on /vapi/*.

# --- stage 1: fetch upstream source at the pinned commit ---------------
# alpine/git is a small image that ships git without the rest of a build
# toolchain. We clone without checkout (saves the working-tree write) then
# checkout the exact commit — this pins the build even if upstream's branch
# tip moves.
FROM alpine/git:latest AS source
ARG VAPI_COMMIT=67152695b0acf13dd424905729080fbc80d5a593
WORKDIR /src
RUN git clone --no-checkout https://github.com/roottusk/vapi.git . \
    && git checkout "${VAPI_COMMIT}"

# --- stage 2: build the Laravel app -----------------------------------
# php:7.4-apache matches upstream's Dockerfile. Laravel 8 requires
# php ^7.3|^8.0 (see vapi/composer.json). 7.4 is the version upstream
# tested against, so we keep it rather than chasing 8.x — the committed
# vendor/ was generated against 7.x and may not resolve cleanly on 8.x
# without re-running composer install.
FROM php:7.4-apache

# Extensions vAPI needs at runtime: mysqli + pdo_mysql for the MySQL DB,
# zip for composer/laravel package operations, plus the mbstring/curl
# that Laravel 8 pulls in transitively. libzip-dev + zlib1g-dev provide
# the zip build headers; libonig-dev provides mbstring's.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libonig-dev \
      libzip-dev \
      zlib1g-dev \
      unzip \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install pdo pdo_mysql mysqli mbstring zip

# composer is needed for the safety-net `composer install` below if the
# committed vendor/ is ever stale. Upstream's own Dockerfile copies it in
# from the composer image; we do the same.
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

# vAPI's Laravel app lives in the `vapi/` subdirectory of the repo, not at
# the repo root. The compose + preflight-vapi.sh both expect it at
# /var/www/html/vapi (artisan at /var/www/html/vapi/artisan, .env at
# /var/www/html/vapi/.env). Keep that path.
COPY --from=source /src/vapi /var/www/html/vapi

# Upstream ships a SQL seed dump at database/vapi.sql at the REPO ROOT
# (not under vapi/ — that subdir holds Laravel's migrations/factories/
# seeders). Verified via `gh api repos/roottusk/vapi/contents/database`
# and a manual clone of the pinned commit. The quick-demo compose copies
# this out of the image via a one-shot `vapi-seed` sidecar into a named
# volume mounted at mysql's /docker-entrypoint-initdb.d, so MySQL imports
# it on first init. `php artisan migrate` is NOT a working path —
# upstream's `flags` migration has a column-name bug in up(). The SQL
# dump is the only reproducible seed mechanism.
COPY --from=source /src/database/vapi.sql /vapi-seed/vapi.sql
WORKDIR /var/www/html/vapi

# Upstream ships a committed vendor/ + composer.lock, so in the happy path
# no install is needed — vendor/autoload.php is already present. We run
# `composer install --no-dev` as a safety net ONLY when the committed
# vendor is missing or incomplete. This keeps the build reproducible if a
# future commit drops vendor/, without re-running composer (and risking a
# resolution drift) on the pinned commit where it's known to work.
RUN if [ ! -f vendor/autoload.php ]; then \
      composer install --no-dev --no-scripts --no-autoloader --ignore-platform-reqs \
      && composer dump-autoload --no-dev --ignore-platform-reqs; \
    fi

# Laravel needs write access to storage/ and bootstrap/cache/ for logs,
# sessions, and the config cache. chown inside the image so it works whether
# or not the app dir is bind-mounted.
RUN chown -R www-data:www-data /var/www/html/vapi/storage /var/www/html/vapi/bootstrap/cache

EXPOSE 80
# APP_KEY is injected at runtime via env (the compose file sets it) — do NOT
# bake one into the image.
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=80"]
