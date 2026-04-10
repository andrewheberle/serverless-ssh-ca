package krl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/api"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	sshkrl "github.com/forfuncsake/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

const Namespace = "krl@com.github.serverless-ssh-ca.andrewheberle"

type Response api.KeyRevocationListResponse

var (
	ErrNoPublicKey       = errors.New("no public key provided for signature verification")
	ErrUnexpectedCA      = errors.New("encountered krl certificate section with unexpected CA")
	ErrUnexpectedSection = errors.New("encountered unexpected section type in krl")
)

func Get(server string, certificatetype api.GetRevocationListEndpointParamsCertificateType, opts ...api.ClientOption) (*Response, error) {
	if opts == nil {
		opts = append(opts, api.WithHTTPClient(client.NewHttpClient()))
	}
	client, err := api.NewClientWithResponses(server, opts...)
	if err != nil {
		return nil, err
	}

	res, err := client.GetRevocationListEndpointWithResponse(context.TODO(), certificatetype)
	if err != nil {
		return nil, err
	}

	if res.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", res.StatusCode())
	}

	slog.Info("response", "res", res)

	return &Response{
		Krl:       res.JSON200.Krl,
		Signature: res.JSON200.Signature,
	}, nil
}

func (r *Response) VerifyStrict(pub ssh.PublicKey) error {
	// parse the KRL
	parsedKrl, err := sshkrl.ParseKRL(r.Krl)
	if err != nil {
		return fmt.Errorf("problem parsing krl: %w", err)
	}

	// check the only sections of the parsed KRL are for certificates
	for _, section := range parsedKrl.Sections {
		if _, ok := section.(*sshkrl.KRLCertificateSection); !ok {
			return ErrUnexpectedSection
		}
	}

	// error here if public key is not provided
	if pub == nil {
		return ErrNoPublicKey
	}

	// unarmor and verify signature
	sig, err := sshsig.Unarmor([]byte(r.Signature))
	if err != nil {
		return fmt.Errorf("problem unarmoring signature: %w", err)
	}

	if err := sshsig.Verify(bytes.NewReader(r.Krl), sig, pub, sshsig.HashSHA512, Namespace); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// check that all sections are for our CA
	pubBytes := pub.Marshal()
	for _, section := range parsedKrl.Sections {
		switch s := section.(type) {
		case *sshkrl.KRLCertificateSection:
			krlCA := s.CA.Marshal()
			if !bytes.Equal(krlCA, pubBytes) {
				return ErrUnexpectedCA
			}
		}
	}

	return nil
}

func (r *Response) Verify(pub ssh.PublicKey) error {
	if err := r.VerifyStrict(pub); err != nil {
		// if the error is that no public key was provided, we can ignore it
		// in this non-strict verification method
		if errors.Is(err, ErrNoPublicKey) {
			return nil
		}
		return err
	}

	return nil
}
