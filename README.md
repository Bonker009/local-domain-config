# kshrd: local HTTPS for kshrd.app and custom domains

Serves `https://kshrd.app`, `https://<name>.kshrd.app` and custom domains such as `https://shop.test` from this PC for demos, with trusted certificates. nginx listens on `127.0.0.2` only, so other devices can't reach it.

Requires nginx, mkcert and PowerShell 7 on `PATH`.

## Usage

`kshrd` works from any folder in PowerShell, cmd and bash because this folder is on the user `PATH`. Bash uses the `kshrd` wrapper script. Terminals opened before it was added need restarting.

```
kshrd help                  List all commands with examples
kshrd help add              Show details for one command (or: kshrd add --help)
kshrd setup                 First run: trust the CA, issue the certificate, update hosts, start nginx
kshrd add demo 3000         https://demo.kshrd.app -> localhost:3000
kshrd add kshrd.app 3000    https://kshrd.app -> localhost:3000
kshrd add shop.test 3000    https://shop.test -> localhost:3000 (any full domain name)
kshrd add shop.test /api 5000       https://shop.test/api -> localhost:5000
kshrd add docs.test ./dist          https://docs.test -> the dist folder
kshrd add db.test 192.168.1.5:8080  https://db.test -> another machine
kshrd add a.test:3000 b.test:4000   Add several sites with one admin prompt
kshrd up                    Add the sites listed in this folder's kshrd.json (kshrd down removes them)
kshrd remove demo           Remove a site (kshrd remove shop.test /api removes one route)
kshrd open shop.test        Open a site in the browser
kshrd logs shop.test        Show its recent requests and errors (-f to keep watching, -Errors for errors only, -Clear to empty them)
kshrd status                Show nginx, each site, and whether its app is up (kshrd list seyha filters, -Json for scripts)
kshrd doctor                Check for problems and suggest a fix for each
kshrd renew                 Reissue certificates that expire soon (-Force for all of them)
kshrd autostart on          Start nginx when you log in (off, status)
kshrd version               Show the version
kshrd start | stop | restart
kshrd teardown              Stop nginx and remove the hosts entries
kshrd teardown -RemoveCA    Also remove the local CA from the trust store
```

nginx does not start with Windows unless you run `kshrd autostart on`. Otherwise, run `kshrd start` after a reboot.

Certificates last a little over two years. `kshrd start` and `kshrd setup` reissue any that have under 30 days left, and `kshrd doctor` warns about them.

Output is coloured in a terminal. Set the `NO_COLOR` environment variable to turn that off.

Changing the hosts file shows a Windows admin prompt. Nothing else needs admin rights.

`kshrd add` asks first if the name is a real website or nothing responds at the target. Add `-Yes` to skip the questions.

A route such as `/api` keeps its path when it calls the app, so `/api/users` arrives as `/api/users`.

A project can list its sites in a `kshrd.json`, with folders relative to that file:

```json
{ "sites": { "shop.test": 3000, "shop.test/api": 5000, "docs.test": "./dist" } }
```

A name containing a dot is used as the full domain. It gets its own certificate in `certs/`, which `kshrd remove` deletes and `kshrd setup` reissues if it is missing. Add `www.shop.test` separately if you want it too.

`sites.json` lists your sites and isn't committed, because it's personal to this PC. `sites.example.json` shows the format. Use `kshrd add` and `kshrd remove` instead of editing it, because they also regenerate the nginx config and hosts entries.

## Known limits

- **Traefik on the same ports:** the Traefik container in `D:\14th Basic Project Demo\Traefix` publishes 80/443 on all addresses when Docker is running. This proxy uses `127.0.0.2` so that both can run together. Hostnames mapped to `127.0.0.1` in the hosts file, such as `apilens.kshrd.app`, keep going to Traefik. To serve one from here, delete its line from the hosts file, then run `kshrd add`.
- **Real domain shadowed:** if `kshrd.app`, its subdomains or a custom domain you add are live on the internet, this PC can't reach the real sites while the hosts entries exist. For made-up names, prefer the reserved `.test` ending. `kshrd teardown` restores access. Entries that were in the hosts file before setup, such as `gitlab.kshrd.app`, stay until you remove them yourself.
- **No wildcards or `.localhost`:** each custom domain is added by its exact name. Browsers resolve `.localhost` names themselves, so those are rejected.
- **Dev server host checks:** Vite needs `server.allowedHosts: ['.kshrd.app']` and Next.js needs `allowedDevOrigins: ['*.kshrd.app']`, plus any custom domain you use. Otherwise they reject the proxied hostname.
- **App config:** OAuth callbacks and CORS allow-lists must use the new URLs.
- **Other browsers and tools:** Chrome and Edge use the Windows trust store. Node and Java tools don't. For Node, set `NODE_EXTRA_CA_CERTS` to the `rootCA.pem` in the folder shown by `mkcert -CAROOT`.
- **CA key:** `rootCA-key.pem` in that same folder can issue certificates this PC trusts for any site. Never share it.

- **Other machines:** nginx looks up a `host:port` target's name when it starts, and won't start if the lookup fails. Use an IP address if the name isn't always available.
- **Static folders:** there is no fallback to `index.html`, so a single-page app's deep links return 404.

## Troubleshooting

Run `kshrd doctor` first. It checks everything below and suggests a fix.

| Symptom | Fix |
|---|---|
| Certificate warning | Run `kshrd setup` again and restart the browser |
| "This app isn't running" page | Start the app, and check the port with `kshrd status` |
| 403 or "host not allowed" from the app | See dev server host checks above |
| nginx won't start | Another program is using port 80 or 443. See `nginx/logs/error.log` |

## Development

Run the tests with `Invoke-Pester .\tests`. They don't touch the real hosts file, nginx or certificates.
