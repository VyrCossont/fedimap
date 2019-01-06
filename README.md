# fedimap

Web server log ingestor to help you build a map of which instances use which IPs to talk to your instance.

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
python -m fedimap > map.yaml
```

## TODO

- Break up main()
- Parallelize DNS lookups and instance API calls using asyncio
- Create `setup.py` and proper entry points
- Set up CI
