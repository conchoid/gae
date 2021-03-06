// Copyright 2017 The LUCI Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloud

import (
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"go.chromium.org/luci/common/clock"
	"go.chromium.org/luci/common/data/caching/lru"
	"go.chromium.org/luci/common/data/rand/mathrand"
	"go.chromium.org/luci/common/errors"

	iamAPI "google.golang.org/api/iam/v1"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// googleTokenSourceKey is a normalized string of service accounts, used as
// a key for oauth2.TokenSource instances in the token source cache.
//
// See TokenSource for more information.
type googleTokenSourceKey string

const (
	// accessTokenMinExpiration is the minimum expiration time for an access
	// token. We prematurely expire the token by this amount to ensure that it is
	// useful once immediately fetched.
	accessTokenMinExpiration = 2 * time.Minute

	// accessTokenExpirationRandomization is a range before an access token
	// expires where we randomly select a token user to refresh the token. This
	// avoids cache stampede on token expiration where the entire service shuts
	// down blocked on token refresh.
	accessTokenExpirationRandomization = 3 * time.Minute

	// publicCertificatesCacheExpiration is the expiration period for cached
	// service account public certificates.
	publicCertificatesCacheExpiration = 1 * time.Hour

	// defaultGoogleServicesCacheSize is the default maximum number of elements
	// that the LRU cache will hold.
	defaultGoogleServicesCacheSize = 1024
)

var (
	infoPublicCertificatesKey = "cloud.Info Public Certificates"
)

// GoogleServiceProvider is a ServiceProvider implementation that uses Google
// services.
type GoogleServiceProvider struct {
	// ServiceAccount is the name of the system's service account.
	ServiceAccount string

	// Cache is the LRU cache to use to store values that are fetched from remote
	// services.
	Cache *lru.Cache
}

// TokenSource implements ServiceProvider's TokenSource API using the default
// Google token source.
//
// The way TokenSource is implemented, the service is vulnerable to a "cache
// stampede" effect where multiple access tokens invalidate at the same time and
// need to be refreshed.
//
// TokenSource instances for a set of scopes are cached so that their access
// tokens will similarly be cached.
func (gsp *GoogleServiceProvider) TokenSource(c context.Context, scopes ...string) (oauth2.TokenSource, error) {
	cbts := contextBoundTokenSource{
		Context:  c,
		cache:    gsp.Cache,
		cacheKey: accessTokenKeyForScopes(scopes),
		makeTokenSource: func(c context.Context) (oauth2.TokenSource, error) {
			return google.DefaultTokenSource(c, scopes...)
		},
	}
	return &cbts, nil
}

// SignBytes implements ServiceProvider's SignBytes using Google Cloud IAM's
// "SignBlob" endpoint.
//
// The SignBlob RPC request that the GAE/Flex service account account is granted
// the "iam.serviceAccountActor" role, which is NOT default.
//
// https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob
func (gsp *GoogleServiceProvider) SignBytes(c context.Context, bytes []byte) (keyName string, signature []byte, err error) {
	// Generate a client to use for the SignBytes API call.
	var ts oauth2.TokenSource
	if ts, err = gsp.TokenSource(c, iamAPI.CloudPlatformScope); err != nil {
		return
	}
	client := oauth2.NewClient(c, ts)

	// Construct an IAM service.
	var svc *iamAPI.Service
	if svc, err = iamAPI.New(client); err != nil {
		err = errors.Annotate(err, "could not get IAM client").Err()
		return
	}

	var resp *iamAPI.SignBlobResponse
	req := svc.Projects.ServiceAccounts.SignBlob(
		fmt.Sprintf("projects/-/serviceAccounts/%s", gsp.ServiceAccount),
		&iamAPI.SignBlobRequest{
			BytesToSign: base64.StdEncoding.EncodeToString(bytes),
		})
	resp, err = req.Context(c).Do()
	if err != nil {
		err = errors.Annotate(err, "SignBlob RPC failed").Err()
		return
	}

	keyName = resp.KeyId
	signature = []byte(resp.Signature)
	return
}

// errTrackingReader wraps an io.Reader and retains an error, if the Reader
// returns an error.
//
// We use this becuase we chain an HTTP response's body Reader with a JSON
// unmarshaller, and want to be able to distinguish between an I/O error and a
// JSON unmarshalling error.
type errTrackingReader struct {
	r   io.Reader
	err error
}

func (etr *errTrackingReader) Read(v []byte) (int, error) {
	cnt, err := etr.r.Read(v)
	if err != nil {
		etr.err = err
	}
	return cnt, err
}

// accessTokenKey is a cache key used to store a minted access token.
//
// An access token is bound to a set of OAuth2 scopes, so it is keyed by a
// normalization of those scopes.
type accessTokenKey string

// contextBoundTokenSource is an oauth2.TokenSource bound to a specific Context.
//
// If an appropriate access token has already been generated and cached, it will
// be immediately reused. Otherwise, a new token will be minted under lock using
// the bound Context. If that minting succeeds, the token will be cached for
// other contextBoundTokenSource to use.
type contextBoundTokenSource struct {
	context.Context

	// cache is the LRU cache to use for caching access tokens.
	cache *lru.Cache

	// cacheKey is the cache key to use for the minted access token.
	cacheKey accessTokenKey

	// makeTokenSource creates a new oauth2.TokenSource bound to the supplied
	// Context. This will be called to generate new access tokens as needed.
	//
	// oauth2.TokenSource will be obtained without any locking, but individual
	// token generation will occur under lock.
	makeTokenSource func(context.Context) (oauth2.TokenSource, error)
}

// Token generates a new OAuth2 token. It is part of the oauth2.TokenSource
// implementation.
func (c *contextBoundTokenSource) Token() (*oauth2.Token, error) {
	now := clock.Now(c)

	// Get the current token value. We do this without locking around the token
	// element.
	if tokIface, ok := c.cache.Get(c, c.cacheKey); ok {
		tok := tokIface.(*oauth2.Token)
		if !c.closeToExpRandomized(now, tok.Expiry, accessTokenExpirationRandomization) {
			return tok, nil
		}
	}

	// Either the token is expired, or we are selected randomly as a refresh case.
	// Get a new TokenSource to refresh the token with.
	ts, err := c.makeTokenSource(c)
	if err != nil {
		return nil, errors.Annotate(err, "failed to create new TokenSource").Err()
	}

	// While refreshing, we lock around the cache key via GetOrCreate in case
	// multiple requests are either selected or have expired.
	tokIface, err := c.cache.GetOrCreate(c, c.cacheKey, func() (interface{}, time.Duration, error) {
		tok, err := ts.Token()
		if err != nil {
			return nil, 0, err
		}

		expiryDelta := tok.Expiry.Sub(now)
		switch {
		case expiryDelta <= 0:
			return nil, 0, errors.Reason("retrieved expired access token (%s < %s)", tok.Expiry, now).Err()
		case expiryDelta > accessTokenMinExpiration:
			// Subtract some time from the token's expiry so we don't use it immediately
			// before it actually expires.
			tok.Expiry = tok.Expiry.Add(-accessTokenMinExpiration)
			expiryDelta -= accessTokenMinExpiration
		}
		return tok, expiryDelta, nil
	})
	if err != nil {
		return nil, errors.Annotate(err, "failed to mint new access token").Err()
	}
	return tokIface.(*oauth2.Token), nil
}

func (c *contextBoundTokenSource) closeToExpRandomized(now, exp time.Time, expRandomization time.Duration) bool {
	switch {
	case now.After(exp):
		return true // expired already
	case now.Add(expRandomization).Before(exp):
		return false // far from expiration
	default:
		// The expiration is close enough. Do the randomization.
		rnd := time.Duration(mathrand.Int63n(c, int64(expRandomization)))
		return now.Add(rnd).After(exp)
	}
}

func accessTokenKeyForScopes(scopes []string) accessTokenKey {
	// Normalize "scopes", removing duplicates and sorting them. This will create
	// an optimal deterministic key for a given set of scopes, regardless of their
	// order.
	scopesMap := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scopesMap[scope] = struct{}{}
	}
	scopes = make([]string, 0, len(scopesMap))
	for scope := range scopesMap {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	return accessTokenKey(strings.Join(scopes, "\x00"))
}
