# certdb usage

Using a database enables additional functionality for existing commands when a
db config is provided:

 - `sign` and `gencert` add a certificate to the certdb after signing it
 - `serve` enables database functionality for the sign and revoke endpoints

A database is required for the following:

 - `revoke` marks certificates revoked in the database with an optional reason
 - `ocsprefresh` refreshes the table of cached OCSP responses
 - `ocspdump` outputs cached OCSP responses in a concatenated base64-encoded format

## OCSP response records and lookup conventions

The `ocsp_responses` table stores pre-signed OCSP responses keyed by
`(serial_number, authority_key_identifier)`. Two different key identifier
conventions coexist and must not be confused:

 - The stored `authority_key_identifier` is producer-specific. `ocsprefresh`
   writes the lowercase hex form of the certificate's AuthorityKeyId
   extension, and records imported from external vendor CAs use the vendor's
   own convention.
 - An RFC 6960 OCSP request instead carries an `IssuerKeyHash` computed over
   the issuer public key with a hash algorithm chosen by the client
   (SHA-1, SHA-256, SHA-384 or SHA-512). The same issuer therefore yields a
   different `IssuerKeyHash` for different client populations, and none of
   those projections can be assumed to equal a stored AKI.

Because the serial number is the only request field independent of the hash
algorithm, status lookup correlates by serial number: `Accessor.GetOCSPBySerial`
returns every record sharing a serial and the responder selects the current one
(the record with the furthest-future expiry). `Accessor.GetOCSP` remains
available for callers that already hold an exact stored AKI. This keeps the
current response identical for SHA-1 and SHA-256 clients, and keeps records
imported under a vendor convention reachable without rewriting them.

## Setup/Migration

This directory stores [goose](https://bitbucket.org/liamstask/goose/) db migration scripts for various DB backends.
Currently supported:
 - MySQL in mysql
 - PostgreSQL in pg
 - SQLite in sqlite

### Get goose

    go get bitbucket.org/liamstask/goose/cmd/goose

### Use goose to start and terminate a MySQL DB
To start a MySQL using goose:

    goose -path certdb/mysql up

To tear down a MySQL DB using goose

    goose -path certdb/mysql down

Note: the administration of MySQL DB is not included. We assume
the databases being connected to are already created and access control
is properly handled.

### Use goose to start and terminate a PostgreSQL DB
To start a PostgreSQL using goose:

    goose -path certdb/pg up

To tear down a PostgreSQL DB using goose

    goose -path certdb/pg down

Note: the administration of PostgreSQL DB is not included. We assume
the databases being connected to are already created and access control
is properly handled.

### Use goose to start and terminate a SQLite DB
To start a SQLite DB using goose:

    goose -path certdb/sqlite up

To tear down a SQLite DB using goose

    goose -path certdb/sqlite down

## CFSSL Configuration

Several cfssl commands take a -db-config flag. Create a file with a
JSON dictionary:

    {"driver":"sqlite3","data_source":"certs.db"}

or

    {"driver":"postgres","data_source":"postgres://user:password@host/db"}
 
or

    {"driver":"mysql","data_source":"user:password@tcp(hostname:3306)/db?parseTime=true"}
