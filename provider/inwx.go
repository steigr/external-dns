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
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	log "github.com/sirupsen/logrus"
	"github.com/smueller18/goinwx"
	"strconv"
	"strings"
)

// INWX provider type
type inwxProvider struct {
	client  *goinwx.Client
	domains []string
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
	log.Debugf("INWX.Records()")
	if err := p.login(); err == nil {
		defer p.logout()
	} else {
		return nil, err
	}
	domains, err := p.getDomains()
	if err != nil {
		return nil, err
	}
	records, err := p.getRecords(domains)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if strings.Compare(record.Type, "SRV") == 0 {
			record.Content = strings.Join([]string{fmt.Sprintf("%d", record.Prio), record.Content}, " ")
		}
		endpoints = append(endpoints, endpoint.NewEndpointWithTTL(record.Name, record.Type, endpoint.TTL(record.Ttl), record.Content).WithProviderSpecific("Id", fmt.Sprintf("%d", record.Id)))
		if strings.Compare(record.Type, "SRV") == 0 {
			record.Content = strings.Join([]string{fmt.Sprintf("%d", record.Prio), record.Content}, " ")
		}
	}
	return endpoints, nil
}

// ApplyChanges publishes records.
func (p *inwxProvider) ApplyChanges(changes *plan.Changes) error {
	log.Debugf("INWX.ApplyChanges()")
	if err := p.login(); err == nil {
		defer p.logout()
	} else {
		return err
	}
	for _, deleteChange := range changes.Delete {
		log.Debugf("Delete Change")
		log.Debugf(spew.Sdump(deleteChange))
	}
	for _, ep := range changes.Create {
		log.Debugf(spew.Sdump(ep))
		domain := p.getDomainOf(ep.DNSName)
		if len(domain) == 0 {
			p.getDomains()
			domain = p.getDomainOf(ep.DNSName)
			if len(domain) == 0 {
				log.Debugf("Endpoint for %s cannot be created", ep.DNSName)
				continue
			}
		}
		for _, target := range ep.Targets {
			prio := 0
			if ep.RecordType == endpoint.RecordTypeSRV {
				segments := strings.Split(target, " ")
				p, e := strconv.ParseInt(segments[0], 10, 32)
				if e == nil {
					prio = int(p)
				}
				target = strings.Join(segments[1:], " ")
			}
			request := &goinwx.NameserverRecordRequest{
				Domain:   domain,
				Name:     ep.DNSName,
				Ttl:      int(ep.RecordTTL),
				Type:     ep.RecordType,
				Content:  target,
				Priority: prio,
			}
			log.Debugf(spew.Sdump(request))
			if ret, err := p.client.Nameservers.CreateRecord(request); err != nil {
				fmt.Errorf("Record %s cannot be created (%d): %s", ep.DNSName, ret, err)
			}
		}
	}
	for _, updateChange := range changes.UpdateNew {
		log.Debugf("Updating Change")
		log.Debugf(spew.Sdump(updateChange))
	}
	return nil
}

func (p *inwxProvider) login() error {
	return p.client.Account.Login()
}

func (p *inwxProvider) logout() error {
	return p.client.Account.Logout()
}

func (p *inwxProvider) getDomains() ([]string, error) {
	var domains []string
	if inwxNameserverDomains, err := p.client.Nameservers.List(""); err == nil {
		for _, inwxNameserverDomain := range inwxNameserverDomains.Domains {
			domains = append(domains, inwxNameserverDomain.Domain)
		}
	} else {
		return nil, err
	}
	p.domains = domains
	return domains, nil
}

func (p *inwxProvider) getRecords(domains []string) ([]goinwx.NameserverRecord, error) {
	var records []goinwx.NameserverRecord
	for _, domain := range domains {
		if result, err := p.client.Nameservers.Info(&goinwx.NameserverInfoRequest{Domain: domain}); err == nil {
			records = append(records, result.Records...)
		} else {
			return nil, err
		}
	}
	return records, nil
}

// select domain from registered domains
func (p *inwxProvider) getDomainOf(name string) string {

	for _, domain := range p.domains {

		if strings.HasSuffix("."+name, "."+domain) {
			return domain
		}
	}
	return ""
}
