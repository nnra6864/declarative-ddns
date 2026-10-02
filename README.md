# declarative-ddns

> [!WARNING]
> This was made with 2 promtps to Claude Sonnet 5.5 Medium.<br>
> It's made for personal use only, so don't expect any kind of support.

Declarative DNS records for [Spaceship.com](https://www.spaceship.com), with dynamic public-IP support.
Define your records once in a TOML file, grouped by domain.
Any record set to `address = "auto"` follows your current public IP.
Single file, Python 3.11+, no dependencies.

## Installation

```bash
sh -c 'git clone https://github.com/nnra6864/declarative-ddns "${XDG_DATA_HOME:-$HOME/.local/share}/declarative-ddns" && cd "${XDG_DATA_HOME:-$HOME/.local/share}/declarative-ddns"'
```

The first run creates everything it needs and tells you what to do next:

| What             | Where                                                             |
|------------------|-------------------------------------------------------------------|
| Your records     | `~/.config/declarative-ddns/config.toml`                          |
| API key + secret | `~/.config/declarative-ddns/secrets.env` (chmod 600, git-ignored) |
| systemd units    | `~/.config/systemd/user/declarative-ddns.{service,timer}`         |
| Command          | `~/.local/bin/declarative-ddns` (symlink to the clone)            |

The clone can live anywhere.
If you move it, run it once from the new location and the units and symlink are repaired automatically.

## Usage

- Dry run - show what would change
```sh
declarative-ddns
```

- Apply - the first success enables the background timer
```sh
declarative-ddns sync --apply
```

- Print live records as config.toml
```sh
declarative-ddns export DOMAIN
```

- Raw JSON of live records
```sh
declarative-ddns list DOMAIN
```

- Background timer on
```sh
declarative-ddns enable
```

- Background timer off
```sh
declarative-ddns disable
```

- Logs
```sh
journalctl --user -u declarative-ddns
```

## How records are managed

For every (type, name) pair in your config, the config is the source of truth, other records with the same type and name are removed.
Pairs you never mention, and Spaceship's own non-custom records, are never touched.
