/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package test

import (
	"fmt"
	"github.com/go-logr/logr"
	"github.com/miekg/dns"
	"sync"
)

const (
	defaultTTL = 1
)

var requestCount = map[string]int{}

type Handler struct {
	Log        logr.Logger
	TxtRecords map[string][][]string
	Zones      []string
	lock       sync.Mutex
}

// serveDNS implements github.com/miekg/dns.Handler
// Imitates a DNS server
func (b *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	b.lock.Lock()
	defer b.lock.Unlock()
	log := b.Log.WithName("serveDNS")

	m := new(dns.Msg)
	m.SetReply(req)
	defer w.WriteMsg(m)

	log.Info(m.String())

	if requestCount[req.Question[0].Name] < len(b.TxtRecords[req.Question[0].Name]) {
		for _, record := range b.TxtRecords[req.Question[0].Name][requestCount[req.Question[0].Name]] {
			txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", req.Question[0].Name, defaultTTL, record))
			m.Answer = append(m.Answer, txtRR)
		}
		requestCount[req.Question[0].Name]++
	}

	for _, rr := range m.Answer {
		log.Info("responding", "response", rr.String())
	}
}
