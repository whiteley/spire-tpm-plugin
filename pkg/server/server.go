/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/go-attestation/attest"
	"io/ioutil"
	"path/filepath"
	"sync"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	gx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// This compile time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	_ pluginsdk.NeedsLogger = (*TPMAttestorPlugin)(nil)
)

// TPMAttestorPlugin implements the nodeattestor Plugin interface
type TPMAttestorPlugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	configMtx sync.RWMutex
	config    *TPMAttestorPluginConfig

	logger hclog.Logger
}

type TPMAttestorPluginConfig struct {
	TrustDomain string
	CaPath      string `hcl:"ca_path"`
}

func (p *TPMAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(TPMAttestorPluginConfig)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	coreConfig := req.GetCoreConfiguration()
	if coreConfig == nil {
		return nil, status.Error(codes.Unknown, "core configuration is required")
	}
	if coreConfig.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}
	if config.CaPath == "" {
		config.CaPath = "/opt/spire/.data/certs"
	}

	p.setConfig(config)

	return &configv1.ConfigureResponse{}, nil
}

// setConfig replaces the configuration atomically under a write lock.
func (p *TPMAttestorPlugin) setConfig(config *TPMAttestorPluginConfig) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

// getConfig gets the configuration under a read lock.
func (p *TPMAttestorPlugin) getConfig() (*TPMAttestorPluginConfig, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *TPMAttestorPlugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *TPMAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	p.logger.Info("Received attestation request")

	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to receive stream: %v", err)
	}

	attestationData := new(common.AttestationData)
	if err := json.Unmarshal(req.GetPayload(), attestationData); err != nil {
		return status.Errorf(codes.Unknown, "failed to unmarshal attestation data: %v", err)
	}

	leaf, _ := gx509.ParseCertificate(attestationData.EK)

	files, err := ioutil.ReadDir(p.config.CaPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "could not open ca directory: %v", err)
	}

	roots := gx509.NewCertPool()
	for _, file := range files {
		filename := filepath.Join(p.config.CaPath, file.Name())
		certData, err := ioutil.ReadFile(filename)
		if err != nil {
			return status.Errorf(codes.Unknown, "could not read cert data for '%s': %v", filename, err)
		}

		ok := roots.AppendCertsFromPEM(certData)
		if ok {
			continue
		}

		root, err := gx509.ParseCertificate(certData)
		if err == nil {
			roots.AddCert(root)
			continue
		}

		return status.Errorf(codes.Unknown, "could not parse cert data for '%s': %v", filename, err)
	}

	opts := gx509.VerifyOptions{
		Roots: roots,
	}
	_, err = leaf.Verify(opts)
	if err != nil {
		return status.Errorf(codes.Unknown, "could not verify cert: %v", err)
	}

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         leaf.PublicKey,
		AK:         *attestationData.AK,
	}

	secret, ec, err := ap.Generate()
	if err != nil {
		return status.Errorf(codes.Unknown, "could not generate credential challenge: %v", err)
	}

	challenge := &common.Challenge{
		EC: ec,
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return status.Errorf(codes.Unknown, "unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challengeBytes,
		},
	}); err != nil {
		return status.Errorf(codes.Unknown, "unable to send challenge: %v", err)
	}

	challengeResp, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Unknown, "unable to receive challenge response: %v", err)
	}

	response := new(common.ChallengeResponse)
	if err := json.Unmarshal(challengeResp.GetPayload(), response); err != nil {
		return status.Errorf(codes.Unknown, "unable to unmarshal challenge response: %v", err)
	}

	if !bytes.Equal(secret, response.Secret) {
		return status.Errorf(codes.Unknown, "incorrect secret from attestor")
	}

	hashEncoded, err := common.GetPubHash(leaf)
	if err != nil {
		return status.Errorf(codes.Unknown, "could not get public key hash: %v", err)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       common.AgentID(p.config.TrustDomain, hashEncoded),
				SelectorValues: buildSelectors(hashEncoded),
			},
		},
	})
}

func buildSelectors(pubHash string) []string {
	var selectors []string
	selectors = append(selectors, pubHash)
	return selectors
}

func containsKey(keys []string, key string) bool {
	for _, item := range keys {
		if item == key {
			return true
		}
	}
	return false
}
