# Third-party components and notices

Nuluno-owned Access Community code is Apache-2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Third-party components keep their own copyright and license
terms. The community license does not relicense them or any separately obtained
commercial extension.

Direct runtime dependencies declared by this community package:

| Component | Upstream license | Purpose |
|---|---|---|
| `@modelcontextprotocol/client` | Apache-2.0 | Official MCP client and demonstration transports |
| `@modelcontextprotocol/server` | Apache-2.0 | MCP server and stdio bridge |
| `@modelcontextprotocol/node` | Apache-2.0 | Node HTTP transport integration |
| `express` | MIT | HTTP routing |
| `zod` | MIT | Input/schema validation |

Development/build dependencies include `esbuild`, `tsx`, `@types/node` and
`@types/express` (MIT), and `typescript` (Apache-2.0). Their transitive components
have their own notices. The exact selected versions and integrity records are in
`package-lock.json`; consult each installed package's LICENSE/NOTICE and package
metadata when redistributing a dependency, bundle or container. This summary is
not a replacement for those full license texts or a complete per-release SBOM.

Node.js and a container base image, if used, have additional third-party license
files in their own distributions. Preserve the notices of the actual runtime
and image you distribute. No third-party dependency is granted Nuluno trademark,
customer-data, platform-account or commercial-extension rights by this file.

The community runtime does not declare `mailauth`, `postal-mime`, the Gmail
verification/signup implementation or the Threads connector as its own bundled
feature. A commercial extension may carry those separately with its own notices
and license. Do not copy its implementation or dependency notices into a community
release as evidence that those private capabilities are included or accepted.
