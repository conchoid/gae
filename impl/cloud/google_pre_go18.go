// +build !go1.8

package cloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	infoS "github.com/conchoid/gae/service/info"

	"go.chromium.org/luci/common/errors"
	"go.chromium.org/luci/common/retry/transient"

	"golang.org/x/net/context"
)

type certsSorter []infoS.Certificate

func (c certsSorter) Len() int {
	return len(c)
}

func (c certsSorter) Less(i, j int) bool {
	return c[i].KeyName < c[j].KeyName
}

func (c certsSorter) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// PublicCertificates implements ServiceProvider's PublicCertificates using
// Google's public certificate endpoint.
func (gsp *GoogleServiceProvider) PublicCertificates(c context.Context) (certs []infoS.Certificate, err error) {
	// Lock around our certificates. If they are already resolved, then we can
	// quickly return them; otherwise, we will need to load them. This lock
	// prevents concurrent certificate accesses from resulting in multiple
	// remote resource requests.
	v, err := gsp.Cache.GetOrCreate(c, &infoPublicCertificatesKey, func() (interface{}, time.Duration, error) {
		// Request a certificate map from the Google x509 public certificte endpoint.
		//
		// Upon success, the result will be a map of key to PEM-encoded value.
		url := fmt.Sprintf("https://www.googleapis.com/robot/v1/metadata/x509/%s", gsp.ServiceAccount)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, 0, errors.Annotate(err, "could not create HTTP request").Err()
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, 0, errors.Annotate(err, "could not send request to %s", url).Tag(transient.Tag).Err()
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, 0, errors.Annotate(err, "received HTTP %d from %s", resp.StatusCode, url).Tag(transient.Tag).Err()
		}

		var certMap map[string]string
		etr := errTrackingReader{resp.Body, nil}
		if err := json.NewDecoder(&etr).Decode(&certMap); err != nil {
			if etr.err != nil {
				// I/O error, mark as transient.
				return nil, 0, errors.Annotate(err, "could not read HTTP response body").Tag(transient.Tag).Err()
			}
			return nil, 0, errors.Annotate(err, "could not decode HTTP response body").Err()
		}

		// Populate our certificate array and sort by key for determinism.
		certs := make([]infoS.Certificate, 0, len(certMap))
		for key, data := range certMap {
			certs = append(certs, infoS.Certificate{
				KeyName: key,
				Data:    []byte(data),
			})
		}
		sort.Sort(certsSorter(certs))
		return certs, 0, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]infoS.Certificate), nil
}
