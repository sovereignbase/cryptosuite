# Identifier

## Intent

`Identifier` exists to produce opaque identifiers:

- fixed-length
- non-semantic
- presentation-consistent
- safe to expose without leaking resource meaning

An identifier from this package should not reveal what kind of resource it
identifies. It is only an opaque token.

## Current format

Current identifiers are:

- 48 bytes of entropy or digest output
- base64url encoded
- always 64 characters long

That means generated and derived identifiers have the same visible shape.

## API

- `generateOID()` creates a random opaque identifier.
- `deriveOID(bytes)` deterministically maps input bytes to the same opaque
  identifier every time.
- `validateOID(id)` checks presentation only: length and base64url alphabet.

## Non-goals

This package does not try to make identifiers:

- human meaningful
- sortable by resource type
- self-describing
- metadata-carrying

If semantics are needed, they belong in separate application data, not inside
the identifier string.
