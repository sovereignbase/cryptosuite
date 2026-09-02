# Identifier

## Intent

`Identifier` creates opaque identifiers whose byte length and derivation
context are selected by the caller. Identifiers are canonical, unpadded
base64url strings and carry no resource metadata.

## API

- `Identifier.generate(byteLength)` creates an identifier from cryptographically
  random bytes.
- `Identifier.derive(base, domain, byteLength)` derives a deterministic,
  domain-separated identifier.
- `Identifier.validate(value, byteLength)` checks both the decoded byte length
  and canonical base64url representation.

`derive` accepts byte sources directly. Strings are passed as objects and
default to UTF-8; base64 and base64url can be selected explicitly:

```ts
const accountId = await Identifier.derive(
  { value: 'tenant-123' },
  { value: 'account-id' },
  32
)

const importedId = await Identifier.derive(
  { value: 'c291cmNl', encoding: 'base64url' },
  { value: 'account-id' },
  32
)
```

Use a distinct domain for every identifier purpose. The domain separates
otherwise identical base values used in different contexts.

## Import

Import the class directly from its package subpath:

```ts
import { Identifier } from '@sovereignbase/cryptosuite/Identifier'
```

The same methods remain available through `Cryptographic.identifier` from the
package root.
