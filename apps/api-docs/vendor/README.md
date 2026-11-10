# Swagger UI vendor files

The bundle, stylesheet and original upstream notices are unmodified members of the [official swagger-ui-dist 5.34.1 npm distribution](https://www.npmjs.com/package/swagger-ui-dist/v/5.34.1). The matching [upstream release](https://github.com/swagger-api/swagger-ui/releases/tag/v5.34.1) points to commit `d3296954a6b813898d298815ac3e68daa1cf7408`. The upstream Apache-2.0 license, attribution notice and JavaScript bundle license notices accompany the assets.

Registry archive SRI

```text
sha512-VSr8fXfI93obYaQicLJbLUKGRxDojj/SfRJDDLCioGTUBj4BK/Nj4eE9jCeCAnJxVLi7iS+08PbiZLyrQKBkJQ==
```

| File | SHA-256 |
| --- | --- |
| `swagger-ui-bundle.js` | `36eeb4d5640b9c036b1d0f854499af1cceebbdb260b790a03a18be5e8488fbf5` |
| `swagger-ui.css` | `c3cfe8248c4b0b89673600fb829924eafbac6de4bc4b2b06f5f5243483074d0a` |
| `LICENSE` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `NOTICE` | `0d20d1adef18aee3f40dd258172155521ce702ac445cb5f7b7d60ed32dad2fb2` |
| `swagger-ui-bundle.js.LICENSE.txt` | `37eb6e7e59aed57b2c1acf076574b818ea07b74265717e0bd67b59e0baf9abbb` |

To verify or update these files, use a temporary directory and the published [registry tarball](https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-5.34.1.tgz). Compare the archive SHA-512 in Base64 with the SRI above before extracting the five named members.

```sh
npm pack swagger-ui-dist@5.34.1 --ignore-scripts --registry=https://registry.npmjs.org
openssl dgst -sha512 -binary swagger-ui-dist-5.34.1.tgz | openssl base64 -A
for name in swagger-ui-bundle.js swagger-ui.css LICENSE NOTICE swagger-ui-bundle.js.LICENSE.txt
do
  tar -xOf swagger-ui-dist-5.34.1.tgz "package/$name" > "$name"
  shasum -a 256 "$name"
done
```

## Supplemental notices

[Third-party license notices](THIRD-PARTY.LICENSE.txt) accompany the five unchanged upstream files. The inventory follows the supplier source map and the pinned release lock. It records versioned package notices and explains why the list is broader than the components confirmed in the shipped JavaScript. For example, the JavaScript contains the browser inheritance implementation from `inherits` and the scrolling helpers from `zenscroll`.

## Runtime review

The browser uses a fixed same-origin OpenAPI document. Keep query-string configuration, alternate specification imports, the hosted validator and persistent authorization disabled. Restrict submissions to the paths in the returned specification. The verifier operations use JSON bodies.

The shipped JavaScript includes `deepmerge`. The upstream release lock resolves it to 4.3.1, which has an advisory for prototype poisoning of a returned object when the merge accepts crafted input. Swagger Client uses the module in the specification resolver. The application controls the specification, references and resolver configuration. Reassess the advisory if accepting user-provided specifications or resolver options. [Upstream advisory](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) · [Swagger Client resolver](https://github.com/swagger-api/swagger-js/blob/v3.38.4/src/resolver/specmap/lib/index.js)

The npm advisory review also flagged `qs` from the upstream lock and optional source map. The shipped JavaScript uses `URLSearchParams` for the guarded browser query configuration. The matching Swagger Client request serializer also uses `URLSearchParams`. The optional map has stale module references and does not establish the presence of `qs` in the shipped JavaScript. [Swagger UI configuration source](https://github.com/swagger-api/swagger-ui/blob/v5.34.1/src/core/config/sources/query.js) · [Swagger Client serializer](https://github.com/swagger-api/swagger-js/blob/v3.38.4/src/http/serializers/request/index.js)
