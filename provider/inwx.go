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
	"errors"
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
	log.Debugf("inwxProvider.Records()")
	var endpoints []*endpoint.Endpoint
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
		switch record.Type {
		case endpoint.RecordTypeA, endpoint.RecordTypeCNAME, endpoint.RecordTypeSRV, endpoint.RecordTypeTXT:
			if strings.Compare(record.Type, "SRV") == 0 {
				record.Content = strings.Join([]string{fmt.Sprintf("%d", record.Prio), record.Content}, " ")
			}
			endpoints = append(endpoints, endpoint.NewEndpointWithTTL(record.Name, record.Type, endpoint.TTL(record.Ttl), record.Content).WithProviderSpecific("Id", fmt.Sprintf("%d", record.Id)))
			if strings.Compare(record.Type, "SRV") == 0 {
				record.Content = strings.Join([]string{fmt.Sprintf("%d", record.Prio), record.Content}, " ")
			}
		}
	}
	log.Debugf(spew.Sdump(endpoints))
	return endpoints, nil
}

// ApplyChanges publishes records.
func (p *inwxProvider) ApplyChanges(changes *plan.Changes) (err error) {
	log.Debugf("inwxProvider.ApplyChanges()")
	err = p.login()
	if err == nil {
		defer p.logout()
	} else {
		return err
	}
	for _, ep := range changes.Delete {
		log.Debugf("Delete Change: %v", ep)
		for _, target := range ep.Targets {
			var (
				err error
				id  int
			)

			if len(ep.ProviderSpecific["Id"]) == 0 {
				id, err = p.getIdByNameAndContent(ep.DNSName, ep.RecordType, target)
			} else {
				id, err = p.parseInt(ep.ProviderSpecific["Id"])
			}

			if err != nil {
				log.Debugf("%v", err)
				return err
			}

			if err = p.client.Nameservers.DeleteRecord(id); err != nil {
				log.Debugf("Record %d cannot be deleted", id)
				return err
			}

		}
	}
	for _, ep := range changes.Create {
		log.Debugf("Create Change: %v", ep)
		domain := p.getDomainOf(ep.DNSName)
		if len(domain) == 0 {
			log.Debugf("Endpoint for %s cannot be created", ep.DNSName)
			continue
		}
		for _, target := range ep.Targets {
			target, prio, err := p.getTargetAndPriorityFromTypeAndTarget(ep.RecordType, target)
			if err != nil {
				return err
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
	// TODO: Implement update function
	for _, updateChange := range changes.UpdateNew {
		log.Debugf("Updating Change: %v", updateChange)
	}
	return nil
}

func (p *inwxProvider) login() error {
	log.Debugf("inwxProvider.login()")
	return p.client.Account.Login()
}

func (p *inwxProvider) logout() error {
	log.Debugf("inwxProvider.logout()")
	return p.client.Account.Logout()
}

func (p *inwxProvider) getDomains() ([]string, error) {
	log.Debugf("inwxProvider.getDomains()")
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
	log.Debugf("inwxProvider.getRecords()")
	var records []goinwx.NameserverRecord
	for _, domain := range domains {
		// we are interested in A/CNAME/TXT/SRV-Records only
		for _, recordType := range []string{endpoint.RecordTypeA, endpoint.RecordTypeCNAME, endpoint.RecordTypeTXT, endpoint.RecordTypeSRV} {
			request := &goinwx.NameserverInfoRequest{Domain: domain, Type: recordType}
			if result, err := p.client.Nameservers.Info(request); err == nil {
				records = append(records, result.Records...)
			} else {
				return nil, err
			}

		}
	}
	return records, nil
}

// select domain from registered domains
func (p *inwxProvider) getDomainOf(name string) string {
	log.Debugf("inwxProvider.getDomainOf()")
	updated := false
	for {
		for _, domain := range p.domains {
			if strings.HasSuffix("."+name, "."+domain) {
				return domain
			}
		}
		if updated {
			break
		} else {
			p.getDomains()
		}
		updated = true
	}
	return ""
}

func (p *inwxProvider) getIdByNameAndContent(name, recordType, target string) (id int, err error) {
	log.Debugf("inwxProvider.getIdByNameAndContent()")
	target, prio, err := p.getTargetAndPriorityFromTypeAndTarget(recordType, target)
	if err != nil {
		return 0, err
	}
	request := &goinwx.NameserverInfoRequest{
		Domain:  p.getDomainOf(name),
		Type:    recordType,
		Content: target,
		Prio:    prio,
		Name:    name,
	}

	response, err := p.client.Nameservers.Info(request)

	if err != nil {
		return 0, err
	}

	if len(response.Records) != 1 {
		return 0, errors.New("Record could not be uniquely identified.")
	}
	return response.Records[0].Id, nil
}

func (p *inwxProvider) getTargetAndPriorityFromTypeAndTarget(recordType, target string) (targetOut string, priority int, err error) {
	log.Debugf("inwxProvider.getTargetAndPriorityFromTypeAndTarget()")
	var segments []string

	if strings.Compare(recordType, endpoint.RecordTypeSRV) != 0 {
		return target, 0, nil
	}
	segments = strings.Split(target, " ")
	target = strings.Join(segments[1:], " ")

	priority, err = p.parseInt(segments[0])
	if err != nil {
		return "", 0, err
	}

	return target, priority, nil
}

func (p *inwxProvider) parseInt(in string) (int, error) {
	log.Debugf("inwxProvider.parseInt()")
	i64, err := strconv.ParseInt(in, 10, 32)
	if err != nil {
		return 0, err
	}
	return int(i64), nil
}
