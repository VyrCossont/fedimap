# fedimap

Fediverse server log scanner which builds a map of which instances use which IPs
to talk to your instance.

[//]: # (regenerate with `gh-md-toc --hide-header --hide-footer README.md`)

[//]: # (ToC start)

* [fedimap](#fedimap)
* [Configure your web server](#configure-your-web-server)
* [Development](#development)
  * [Linting](#linting)
  * [Testing](#testing)
  * [Running](#running)
  * [TODO](#todo)

[//]: # (ToC end)

# Configure your web server

`fedimap` uses referrer and user agent information from your access logs, and thus supports
[Combined Log Format](http://fileformats.archiveteam.org/wiki/Combined_Log_Format) only.
It will not work with access logs in
[Common Log Format](http://fileformats.archiveteam.org/wiki/Common_Log_Format).
Most web servers can write access logs in Combined Log Format if requested:

- nginx: [on by default](https://docs.nginx.com/nginx/admin-guide/monitoring/logging/#setting-up-the-access-log)
- Apache 2: [use the `CustomLog` directive with the `combined` format](https://httpd.apache.org/docs/trunk/logs.html#combined)
- Caddy: [use the `log` directive with the `"{combined}"` format](https://caddyserver.com/docs/log#log-format)

# Development

## Setup

```bash
python3.7 -m venv --prompt 'fedimap' .venv
. .venv/bin/activate
pip install --upgrade pip
pip install --requirement requirements.txt --requirement requirements-dev.txt
```

## Linting

```bash
flake8 fedimap --max-line-length 100
```

## Testing

```bash
python -m unittest discover fedimap '*_test.py'
```

## Running

```bash
python -m fedimap access.log > map.yaml
```

## TODO

- Break up `main()`
- Parallelize DNS lookups and instance API calls using `asyncio`/`aiohttp`/`aiodns`
- Create `setup.py` and proper entry points
- Set up CI
- Set up Sphinx docs
    - Convert readme to rST
    - Document output format
- Add test coverage reports
- Figure out which versions of Python this works on
