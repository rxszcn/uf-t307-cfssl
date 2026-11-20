package certdb

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jmoiron/sqlx/types"
)

// CertificateRecord encodes a certificate and its metadata
// that will be recorded in a database.
type CertificateRecord struct {
	Serial    string    `db:"serial_number"`
	AKI       string    `db:"authority_key_identifier"`
	CALabel   string    `db:"ca_label"`
	Status    string    `db:"status"`
	Reason    int       `db:"reason"`
	Expiry    time.Time `db:"expiry"`
	RevokedAt time.Time `db:"revoked_at"`
	PEM       string    `db:"pem"`
	// the following fields will be empty for data inserted before migrate 002 has been run.
	IssuedAt     *time.Time     `db:"issued_at"`
	NotBefore    *time.Time     `db:"not_before"`
	MetadataJSON types.JSONText `db:"metadata"`
	SANsJSON     types.JSONText `db:"sans"`
	CommonName   sql.NullString `db:"common_name"`
}

// SetMetadata sets the metadata json
func (c *CertificateRecord) SetMetadata(meta map[string]interface{}) error {
	marshaled, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	c.MetadataJSON = types.JSONText(marshaled)
	return nil
}

// GetMetadata returns the json metadata
func (c *CertificateRecord) GetMetadata() (map[string]interface{}, error) {
	var meta map[string]interface{}
	err := c.MetadataJSON.Unmarshal(&meta)
	return meta, err
}

// SetSANs sets the list of sans
func (c *CertificateRecord) SetSANs(meta []string) error {
	marshaled, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	c.SANsJSON = types.JSONText(marshaled)
	return nil
}

// GetSANs returns the json SANs
func (c *CertificateRecord) GetSANs() ([]string, error) {
	var sans []string
	err := c.SANsJSON.Unmarshal(&sans)
	return sans, err
}

// OCSPRecord encodes a OCSP response body and its metadata
// that will be recorded in a database.
//
// The AKI field stores the authority key identifier of the issuing CA as a
// lowercase hex string. It reflects the convention used by the producer of
// the record (for example ocsprefresh stores
// hex(certificate.AuthorityKeyId), and records imported from external vendor
// CAs follow the vendor's own key identifier convention). It is NOT derived
// from the hash algorithm of an OCSP request: an RFC 6960 CertID carries
// either a SHA-1, SHA-256, SHA-384 or SHA-512 hash of the issuer public key
// depending on what the client chose, so none of those projections can be
// assumed to match a stored AKI. Status lookups therefore correlate records
// by SerialNumber first; see GetOCSPBySerial.
type OCSPRecord struct {
	// Serial is the certificate serial number as a decimal string. It is the
	// algorithm-independent correlation key for an OCSP status lookup.
	Serial string `db:"serial_number"`
	// AKI is the authority key identifier of the issuing CA as a lowercase hex
	// string, recorded under the convention of the record's producer. See the
	// type comment above.
	AKI string `db:"authority_key_identifier"`
	// Body is the DER-encoded, pre-signed OCSP response.
	Body string `db:"body"`
	// Expiry is when the cached response stops being considered current.
	Expiry time.Time `db:"expiry"`
}

// Accessor abstracts the CRUD of certdb objects from a DB.
type Accessor interface {
	InsertCertificate(cr CertificateRecord) error
	GetCertificate(serial, aki string) ([]CertificateRecord, error)
	GetUnexpiredCertificates() ([]CertificateRecord, error)
	GetRevokedAndUnexpiredCertificates() ([]CertificateRecord, error)
	GetUnexpiredCertificatesByLabel(labels []string) (crs []CertificateRecord, err error)
	GetRevokedAndUnexpiredCertificatesByLabel(label string) ([]CertificateRecord, error)
	GetRevokedAndUnexpiredCertificatesByLabelSelectColumns(label string) ([]CertificateRecord, error)
	RevokeCertificate(serial, aki string, reasonCode int) error
	InsertOCSP(rr OCSPRecord) error
	GetOCSP(serial, aki string) ([]OCSPRecord, error)
	// GetOCSPBySerial retrieves every OCSPRecord carrying serial, regardless of
	// the authority key identifier convention each record was stored under.
	// OCSP request hash algorithms vary between clients (RFC 6960 allows
	// SHA-1/SHA-256/SHA-384/SHA-512 CertIDs), so the request's issuer key hash
	// cannot be used to correlate against records keyed by a producer-specific
	// AKI; the serial number is the stable, hash-independent correlation key.
	// When several records share a serial (for example during key re-issuance),
	// all of them are returned and the caller selects the current one.
	GetOCSPBySerial(serial string) ([]OCSPRecord, error)
	GetUnexpiredOCSPs() ([]OCSPRecord, error)
	UpdateOCSP(serial, aki, body string, expiry time.Time) error
	UpsertOCSP(serial, aki, body string, expiry time.Time) error
}
