/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	log "github.com/sirupsen/logrus"
	"github.com/smueller18/goinwx"
)

// INWX provider type
type inwxProvider struct {
	client *goinwx.Client
}

// NewInwxProvider is a factory function for INWX providers
func NewInwxProvider(username string, password string, dryRun bool) (*inwxProvider, error) {
	p := &inwxProvider{
		client: goinwx.NewClient(username, password, &goinwx.ClientOptions{Sandbox: dryRun}),
	}

	if err := p.login(); err != nil {
		return nil, err
	} else {
		defer p.logout()
	}

	log.Infof("Configured INWX")

	return p, nil
}

// Records returns the list of records.
func (p *inwxProvider) Records() ([]*endpoint.Endpoint, error) {
	var endpoints []*endpoint.Endpoint
	return endpoints, nil
}

// ApplyChanges publishes records.
func (p *inwxProvider) ApplyChanges(changes *plan.Changes) error {
	return nil
}

func (p *inwxProvider) login() error {
	return p.client.Account.Login()
}

func (p *inwxProvider) logout() error {
	return p.client.Account.Logout()
}
