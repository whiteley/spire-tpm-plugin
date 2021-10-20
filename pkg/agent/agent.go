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

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"
	"sync"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
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

	tpm *attest.TPM
}

type TPMAttestorPluginConfig struct {
	TrustDomain string
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

func (p *TPMAttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	attestationData, aik, err := p.generateAttestationData()
	if err != nil {
		return status.Errorf(codes.Unknown, "failed to generate attestation data: %v", err)
	}

	attestationDataBytes, err := json.Marshal(attestationData)
	if err != nil {
		return status.Errorf(codes.Unknown, "failed to marshal attestation data to json: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationDataBytes,
		},
	}); err != nil {
		return status.Errorf(codes.Unknown, "failed to send attestation data: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Unknown, "failed to receive challenge: %v", err)
	}

	challenge := new(common.Challenge)
	if err := json.Unmarshal(resp.GetChallenge(), challenge); err != nil {
		return status.Errorf(codes.Unknown, "failed to unmarshal challenge: %v", err)
	}

	response, err := p.calculateResponse(challenge.EC, aik)
	if err != nil {
		return status.Errorf(codes.Unknown, "failed to calculate response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return status.Errorf(codes.Unknown, "unable to marshal challenge response: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: responseBytes,
		},
	}); err != nil {
		return status.Errorf(codes.Unknown, "unable to send challenge response: %v", err)
	}

	return nil
}

func (p *TPMAttestorPlugin) calculateResponse(ec *attest.EncryptedCredential, aikBytes []byte) (*common.ChallengeResponse, error) {
	tpm := p.tpm
	if tpm == nil {
		var err error
		tpm, err = attest.OpenTPM(&attest.OpenConfig{
			TPMVersion: attest.TPMVersion20,
		})
		if err != nil {
			return nil, status.Errorf(codes.Unknown, "failed to connect to tpm: %v", err)
		}
		defer tpm.Close()
	}

	aik, err := tpm.LoadAK(aikBytes)
	if err != nil {
		return nil, err
	}
	defer aik.Close(tpm)

	secret, err := aik.ActivateCredential(tpm, *ec)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to activate credential: %v", err)
	}
	return &common.ChallengeResponse{
		Secret: secret,
	}, nil
}

func (p *TPMAttestorPlugin) generateAttestationData() (*common.AttestationData, []byte, error) {
	tpm := p.tpm
	if tpm == nil {
		var err error
		tpm, err = attest.OpenTPM(&attest.OpenConfig{
			TPMVersion: attest.TPMVersion20,
		})
		if err != nil {
			return nil, nil, status.Errorf(codes.Unknown, "failed to connect to tpm: %v", err)
		}
		defer tpm.Close()
	}

	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, err
	}
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, nil, err
	}
	defer ak.Close(tpm)
	params := ak.AttestationParameters()

	var ekCert *x509.Certificate
	for _, ek := range eks {
		if ek.Certificate != nil && ek.Certificate.PublicKeyAlgorithm == x509.RSA {
			ekCert = ek.Certificate
			break
		}
	}

	if ekCert == nil {
		return nil, nil, errors.New("no EK available")
	}

	aikBytes, err := ak.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return &common.AttestationData{
		EK: ekCert.Raw,
		AK: &params,
	}, aikBytes, nil
}
