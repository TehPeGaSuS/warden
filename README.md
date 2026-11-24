# Warden

Warden is a set of IRC services (NickServ, ChanServ, OperServ and friends) for IRC networks. It is a fork of [Anope](https://github.com/anope/anope), focused on networks with large lists (forbids, users, akills) and on UnrealIRCd.

> [!IMPORTANT]
> **Warden is developed with AI assistance** (Claude). Every change is reviewed and tested by a human on real networks before it is released, but if that is a deal-breaker for you, Anope itself is the better choice.
>
> **Warden is not affiliated with or endorsed by the Anope team.** Please do not ask for Warden support in Anope's channels, forums or issue tracker. Report Warden problems here.
> A special thanks to [@ryanwohara](https://github.com/ryanwohara) for the tool(s) that made this possible!

## Why a fork?

Warden started from problems that hit big networks hard, such as services freezing for many seconds while reloading a forbid list of 10,000 entries, and list commands that cannot page through large results. Fixing those well needs changes Anope is not taking right now, so Warden takes them on separately.


Warden is a clean break: it has its own name, namespace, binary and config file names. Anope's history and copyright stay intact, and the code remains GPLv2, so anything useful here is free for Anope to take.

## Supported IRCds

| Tier | IRCd | What it means |
|---|---|---|
| 1 | UnrealIRCd 6 | Tested on every release and run in production |
| 2 | InspIRCd 4, Solanum, ircd-hybrid 8.2, ngIRCd | Best effort: tested, fixed when they break |
| Unsupported | Everything else inherited from Anope (e.g. plexus) | Still in the tree, never tested, may be removed |
| Removed | ircd-ratbox | No release since 3.0.10 (January 2016). Solanum, which descends from it, is supported |

Windows builds are inherited from Anope and **unsupported**: they may work, but nobody tests them.

## Quick start

```
$ ./Config
$ make -C build install
```

Then, in the install directory:

```
$ cp conf/warden.example.conf conf/warden.conf
```

Edit `warden.conf` (uplink, serverinfo and the protocol module) and run `./bin/warden`. When asked for logs for a bug report, run `./bin/warden --support`.

The example configuration includes the other `*.example.conf` files. To change one of them, copy it (e.g. `modules.example.conf` to `modules.conf`) and point the matching `include` in `warden.conf` at the copy.

### Coming from Anope

Warden reads an existing `anope.conf` and `anope.json` if `warden.conf` / `warden.json` are not there, and warns you to rename them. The RPC interface also accepts the old `anope.*` method names for now, so tools like MagIRC keep working. XML-RPC has been removed; use the `jsonrpc` module instead.

## Extra modules

Modules that need extra libraries (such as the SQL and LDAP modules) are enabled with `./extras` from the source directory; then re-run `./Config` and `make -C build install`. Third-party modules go in `modules/third`.

## Help and bug reports

* **Bugs:** [GitHub Issues](https://github.com/TehPeGaSuS/warden/issues)
* **Questions and help:** [GitHub Discussions](https://github.com/TehPeGaSuS/warden/discussions)
* **Security issues:** report them privately, see [SECURITY.md](.github/SECURITY.md)

## Credits and licence

Warden is built on more than two decades of work by the Anope contributors; see [docs/AUTHORS.txt](docs/AUTHORS.txt). It is free software under version 2 of the GNU General Public License; see [docs/LICENSE.txt](docs/LICENSE.txt).
