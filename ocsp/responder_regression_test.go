package ocsp

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/helpers"

	goocsp "golang.org/x/crypto/ocsp"
)

// regressionDB opens the shared sqlite test database. testdb.SQLiteDB truncates
// the tables on every open, so every regression starts from an empty store.
func regressionDB(t *testing.T) *sql.Accessor {
	t.Helper()
	return sql.NewAccessor(testdb.SQLiteDB("testdata/sqlite_test.db"))
}

func regressionCertAndIssuer(t *testing.T) (cert, issuerPEM []byte) {
	t.Helper()
	var err error
	cert, err = os.ReadFile("testdata/cert.pem")
	if err != nil {
		t.Fatalf("read cert: %s", err)
	}
	issuerPEM, err = os.ReadFile("testdata/ca.pem")
	if err != nil {
		t.Fatalf("read issuer: %s", err)
	}
	return cert, issuerPEM
}

// regressionRequest builds a parsed RFC 6960 OCSP request for the test leaf
// using the given issuer hash algorithm.
func regressionRequest(t *testing.T, hash crypto.Hash) *goocsp.Request {
	t.Helper()
	certPEM, issuerPEM := regressionCertAndIssuer(t)
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse cert: %s", err)
	}
	issuer, err := helpers.ParseCertificatePEM(issuerPEM)
	if err != nil {
		t.Fatalf("parse issuer: %s", err)
	}
	der, err := goocsp.CreateRequest(cert, issuer, &goocsp.RequestOptions{Hash: hash})
	if err != nil {
		t.Fatalf("create %s request: %s", hash, err)
	}
	req, err := goocsp.ParseRequest(der)
	if err != nil {
		t.Fatalf("parse request: %s", err)
	}
	return req
}

// regressionSignedBody signs a real OCSP response for the test leaf with the
// given NextUpdate, so the returned bytes parse as a successful, Good response.
func regressionSignedBody(t *testing.T, nextUpdate time.Time) []byte {
	t.Helper()
	certPEM, issuerPEM := regressionCertAndIssuer(t)
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse cert: %s", err)
	}
	issuer, err := helpers.ParseCertificatePEM(issuerPEM)
	if err != nil {
		t.Fatalf("parse issuer: %s", err)
	}
	key, err := helpers.ParsePrivateKeyPEM(mustReadFile(t, "testdata/ca-key.pem"))
	if err != nil {
		t.Fatalf("parse key: %s", err)
	}
	template := goocsp.Response{
		Status:       goocsp.Good,
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   nextUpdate,
	}
	body, err := goocsp.CreateResponse(issuer, cert, template, key)
	if err != nil {
		t.Fatalf("create response: %s", err)
	}
	return body
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %s", path, err)
	}
	return b
}

// regressionServe drives the full HTTP responder with a GET carrying the
// marshalled request, mirroring the gateway/direct production path.
func regressionServe(t *testing.T, src Source, req *goocsp.Request) *httptest.ResponseRecorder {
	t.Helper()
	der, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal request: %s", err)
	}
	rw := httptest.NewRecorder()
	NewResponder(src, nil).ServeHTTP(rw, &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: base64.StdEncoding.EncodeToString(der)},
	})
	return rw
}

// TestOCSPHashAlgorithmIndependence is the regression for the incident where
// clients upgraded to SHA-256 CertIDs all received unauthorized responses for
// a certificate whose current OCSPRecord was stored under the SHA-1/AKI
// convention. The current response for a serial must not depend on the hash
// algorithm the requester chose.
//
// Constructed input matrix (request hash x issuer record convention):
//
//	Group 1: SHA-1 request  -> record under the standard (SHA-1/AKI) convention
//	Group 2: SHA-256 request -> record under the standard (SHA-1/AKI) convention
//	Group 3: SHA-256 request -> record under a vendor-specific AKI convention
//	(see TestOCSPVendorKeyIdentifierRecord)
func TestOCSPHashAlgorithmIndependence(t *testing.T) {
	accessor := regressionDB(t)
	reqSHA1 := regressionRequest(t, crypto.SHA1)
	reqSHA256 := regressionRequest(t, crypto.SHA256)

	if reqSHA1.HashAlgorithm != crypto.SHA1 || reqSHA256.HashAlgorithm != crypto.SHA256 {
		t.Fatalf("unexpected request hash algorithms: %v / %v",
			reqSHA1.HashAlgorithm, reqSHA256.HashAlgorithm)
	}
	sha1AKI := hex.EncodeToString(reqSHA1.IssuerKeyHash)
	sha256AKI := hex.EncodeToString(reqSHA256.IssuerKeyHash)
	if sha1AKI == sha256AKI {
		t.Fatal("SHA-1 and SHA-256 issuer key hashes unexpectedly identical")
	}
	t.Logf("serial=%s", reqSHA1.SerialNumber.String())
	t.Logf("SHA-1 request IssuerKeyHash=%s (%d bytes)", sha1AKI, len(reqSHA1.IssuerKeyHash))
	t.Logf("SHA-256 request IssuerKeyHash=%s (%d bytes)", sha256AKI, len(reqSHA256.IssuerKeyHash))

	// The legacy/current record is keyed by the SHA-1 convention, exactly as
	// ocsprefresh writes hex(cert.AuthorityKeyId) into the store.
	body := regressionSignedBody(t, time.Now().AddDate(0, 1, 0))
	record := certdb.OCSPRecord{
		Serial: reqSHA1.SerialNumber.String(),
		AKI:    sha1AKI,
		Body:   string(body),
		Expiry: time.Now().AddDate(0, 0, 2),
	}
	if err := accessor.InsertOCSP(record); err != nil {
		t.Fatalf("insert OCSP record: %s", err)
	}
	src := NewDBSource(accessor)

	// Matrix Group 1: SHA-1 request against the standard-convention record.
	t.Run("Group1_SHA1_request_standard_record", func(t *testing.T) {
		got, _, err := src.Response(reqSHA1)
		if err != nil {
			t.Fatalf("SHA-1 lookup failed: %s", err)
		}
		if !bytesEqual(got, body) {
			t.Fatal("SHA-1 lookup did not return the stored current record")
		}
		rw := regressionServe(t, src, reqSHA1)
		if rw.Code != http.StatusOK {
			t.Fatalf("HTTP status = %d, want 200", rw.Code)
		}
		if !bytesEqual(rw.Body.Bytes(), body) {
			t.Fatal("SHA-1 HTTP body is not the signed DER response")
		}
		t.Logf("Group 1: SHA-1 request -> HTTP status=%d body_prefix=%x (successful OCSP DER)",
			rw.Code, rw.Body.Bytes()[:8])
	})

	// Matrix Group 2: SHA-256 request against the same standard-convention record.
	t.Run("Group2_SHA256_request_standard_record", func(t *testing.T) {
		got, _, err := src.Response(reqSHA256)
		if err != nil {
			t.Logf("SHA-256 lookup error: %v", err)
			t.Fatalf("SHA-256 lookup must reach the current record regardless of request hash, got %s", err)
		}
		if !bytesEqual(got, body) {
			t.Fatal("SHA-256 lookup returned a different response than the SHA-1 path")
		}
		rw := regressionServe(t, src, reqSHA256)
		if rw.Code != http.StatusOK {
			t.Fatalf("HTTP status = %d, want 200", rw.Code)
		}
		if !bytesEqual(rw.Body.Bytes(), body) {
			t.Fatal("SHA-256 HTTP body differs from SHA-1 path")
		}
		parsed, err := goocsp.ParseResponse(rw.Body.Bytes(), nil)
		if err != nil {
			t.Fatalf("response no longer parses: %s", err)
		}
		if parsed.Status != goocsp.Good {
			t.Fatalf("response status = %d, want Good", parsed.Status)
		}
		t.Logf("Group 2: SHA-256 request -> HTTP status=%d body_prefix=%x (successful OCSP DER, status Good)",
			rw.Code, rw.Body.Bytes()[:8])
	})

	t.Run("unknown serial stays unauthorized", func(t *testing.T) {
		unknown := &goocsp.Request{
			HashAlgorithm:  crypto.SHA256,
			IssuerNameHash: reqSHA256.IssuerNameHash,
			IssuerKeyHash:  reqSHA256.IssuerKeyHash,
			SerialNumber:   big.NewInt(0xdeadbeef),
		}
		if _, _, err := src.Response(unknown); err != ErrNotFound {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		rw := regressionServe(t, src, unknown)
		if !bytesEqual(rw.Body.Bytes(), unauthorizedErrorResponse) {
			t.Fatalf("body = %x, want unauthorized %x", rw.Body.Bytes(), unauthorizedErrorResponse)
		}
		t.Logf("unknown serial -> HTTP status=%d body=%x (OCSP unauthorized)",
			rw.Code, rw.Body.Bytes())
	})
}

// TestOCSPVendorKeyIdentifierRecord covers Matrix Group 3: a SHA-256 request
// for a certificate whose status record was imported from an external vendor
// CA under the vendor's own authority key identifier convention, matching
// neither the SHA-1 nor the SHA-256 hash carried by a request. Several records
// for one serial may coexist during re-issuance; the current record (furthest
// expiry) must be served to every client, independently of hash.
func TestOCSPVendorKeyIdentifierRecord(t *testing.T) {
	accessor := regressionDB(t)
	reqSHA1 := regressionRequest(t, crypto.SHA1)
	reqSHA256 := regressionRequest(t, crypto.SHA256)

	// Simulate a vendor-specific key identifier: shaped like a 20-byte key id
	// but deliberately equal to neither request hash projection.
	vendorSum := sha256.Sum256([]byte("vendor authority key identifier convention"))
	vendorAKI := hex.EncodeToString(vendorSum[:20])
	sha1AKI := hex.EncodeToString(reqSHA1.IssuerKeyHash)
	sha256AKI := hex.EncodeToString(reqSHA256.IssuerKeyHash)
	if vendorAKI == sha1AKI || vendorAKI == sha256AKI {
		t.Fatal("synthetic vendor AKI collides with a request hash")
	}

	serial := reqSHA1.SerialNumber.String()
	vendorBody := regressionSignedBody(t, time.Now().AddDate(1, 0, 0))

	// Matrix Group 3, single-record case: the only stored status record for
	// the serial uses the vendor convention (no standard-convention copy).
	if err := accessor.InsertOCSP(certdb.OCSPRecord{
		Serial: serial,
		AKI:    vendorAKI,
		Body:   string(vendorBody),
		Expiry: time.Now().AddDate(0, 0, 30),
	}); err != nil {
		t.Fatalf("insert vendor record: %s", err)
	}
	src := NewDBSource(accessor)

	// Matrix Group 3: SHA-256 request against the vendor-convention record.
	t.Run("Group3_SHA256_request_vendor_record", func(t *testing.T) {
		got, _, err := src.Response(reqSHA256)
		if err != nil {
			t.Fatalf("SHA-256 lookup against vendor record failed: %s", err)
		}
		if !bytesEqual(got, vendorBody) {
			t.Fatal("SHA-256 lookup did not return the vendor-convention record")
		}
		rw := regressionServe(t, src, reqSHA256)
		if rw.Code != http.StatusOK || !bytesEqual(rw.Body.Bytes(), vendorBody) {
			t.Fatalf("HTTP path status=%d body_match=%v, want 200 + vendor body",
				rw.Code, bytesEqual(rw.Body.Bytes(), vendorBody))
		}
		parsed, err := goocsp.ParseResponse(rw.Body.Bytes(), nil)
		if err != nil || parsed.Status != goocsp.Good {
			t.Fatalf("vendor response not a parseable Good response: err=%v status=%v",
				err, parsed)
		}
		t.Logf("Group 3: SHA-256 request -> HTTP status=%d body_prefix=%x (vendor-convention record, status Good)",
			rw.Code, rw.Body.Bytes()[:8])
	})

	// Re-issuance edge: a second, older record for the same serial appears
	// under the legacy convention. The current (furthest-expiry) answer must
	// stay identical for both request hashes and for both transport paths.
	legacyBody := regressionSignedBody(t, time.Now().AddDate(0, 1, 0))
	if bytesEqual(legacyBody, vendorBody) {
		t.Fatal("test setup produced identical response bodies")
	}
	if err := accessor.InsertOCSP(certdb.OCSPRecord{
		Serial: serial,
		AKI:    sha1AKI,
		Body:   string(legacyBody),
		Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert legacy record: %s", err)
	}

	t.Run("current answer identical across request hashes and transport paths", func(t *testing.T) {
		gotSHA1, _, err := src.Response(reqSHA1)
		if err != nil {
			t.Fatalf("SHA-1 lookup failed: %s", err)
		}
		gotSHA256, _, err := src.Response(reqSHA256)
		if err != nil {
			t.Fatalf("SHA-256 lookup failed: %s", err)
		}
		if !bytesEqual(gotSHA1, gotSHA256) || !bytesEqual(gotSHA1, vendorBody) {
			t.Fatal("current response diverges between request hash algorithms")
		}
		// Direct Source lookup vs the gateway HTTP path must agree as well.
		rw := regressionServe(t, src, reqSHA256)
		if !bytesEqual(rw.Body.Bytes(), gotSHA256) {
			t.Fatal("HTTP responder body differs from direct source lookup")
		}
		if etag := rw.Header().Get("ETag"); etag == "" {
			t.Fatal("response missing ETag")
		}
		t.Logf("coexisting records: SHA-1 and SHA-256 both served current body_prefix=%x",
			vendorBody[:8])
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
