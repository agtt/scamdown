# Contributing

## Add or fix a platform

Platforms live in [`src/providers.ts`](src/providers.ts). Each entry says how to recognise the service and where it takes reports:

```ts
{
  id: "render",
  name: "Render",
  role: "host",
  match: { hostSuffix: ["onrender.com"], header: [["x-render-origin-server", /./]] },
  channels: [email("abuse@render.com")],
}
```

- `match` can use `hostSuffix`, `cnameSuffix`, `nsSuffix`, `asn`, `ipPrefix` and response `header`s. If you add a header, also add it to `KEEP_HEADERS` in `src/net/trace.ts`.
- Only use contacts published by the provider itself, and link that page in the PR. Contacts copied from forums go stale and send reports into the void.
- Registrar abuse e-mails come live from RDAP, so registrars only need an entry in `REGISTRAR_FORMS` when they have a dedicated form.
- National reporting goes in `AUTHORITIES`, keyed by ISO country code.

If a contact stopped working, open an issue with the "Contact changed" template.

## Develop

```sh
bun install
bun test
bun src/cli.ts report https://example.com
bun src/cli.ts web
```

Keep dependencies few, and never add code that executes the scam page.
