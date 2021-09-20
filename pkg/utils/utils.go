package utils

import (
	"io"
	"net/http"
)

func HttpRequest(endpoint string, m string, header map[string]string, content io.Reader, contentLength string) (*http.Response, error) {
	client := &http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(header) > 0 {
				for k, v := range header {
					r.Header.Add(k, v)
				}
			}
			if contentLength != "" {
				r.Header.Add("Content-Length", contentLength)
			}
			r.URL.Opaque = r.URL.Path
			return nil
		},
	}
	r, err := http.NewRequest(m, endpoint, content) // URL-encoded payload
	if err != nil {
		return nil, err
	}
	if len(header) > 0 {
		for k, v := range header {
			r.Header.Add(k, v)
		}
	}
	if contentLength != "" {
		r.Header.Add("Content-Length", contentLength)
	}

	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	return res, nil
}
