// Copyright 2015 The LUCI Authors.
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

package memory

import (
	"fmt"

	"github.com/conchoid/gae/impl/dummy"
	"github.com/conchoid/gae/service/info"
	"github.com/conchoid/gae/service/info/support"

	"golang.org/x/net/context"
)

var giContextKey = "holds a *globalInfoData"

var defaultGlobalInfoData = globalInfoData{
	// versionID returns X.Y where Y is autogenerated by appengine, and X is
	// whatever's in app.yaml.
	versionID: "testVersionID.1",
	requestID: "test-request-id",
}

type globalInfoData struct {
	appID     string
	fqAppID   string
	namespace string
	versionID string
	requestID string
}

func curGID(c context.Context) *globalInfoData {
	if gid, ok := c.Value(&giContextKey).(*globalInfoData); ok {
		return gid
	}
	return &defaultGlobalInfoData
}

func useGID(c context.Context, f func(mod *globalInfoData)) context.Context {
	cur := curGID(c)
	if cur == nil {
		cur = &defaultGlobalInfoData
	}

	clone := *cur
	f(&clone)
	return context.WithValue(c, &giContextKey, &clone)
}

// useGI adds a gae.GlobalInfo context, accessible
// by gae.GetGI(c)
func useGI(c context.Context) context.Context {
	return info.SetFactory(c, func(ic context.Context) info.RawInterface {
		return &giImpl{dummy.Info(), curGID(ic), ic}
	})
}

type giImpl struct {
	info.RawInterface
	*globalInfoData
	c context.Context
}

var _ = info.RawInterface((*giImpl)(nil))

func (gi *giImpl) GetNamespace() string { return gi.namespace }

func (gi *giImpl) Namespace(ns string) (context.Context, error) {
	if err := support.ValidNamespace(ns); err != nil {
		return gi.c, err
	}

	return useGID(gi.c, func(mod *globalInfoData) {
		mod.namespace = ns
	}), nil
}

func (gi *giImpl) AppID() string {
	return gi.appID
}

func (gi *giImpl) FullyQualifiedAppID() string {
	return gi.fqAppID
}

func (gi *giImpl) DefaultVersionHostname() string {
	return fmt.Sprintf("%s.example.com", gi.appID)
}

func (gi *giImpl) IsDevAppServer() bool {
	return true
}

func (gi *giImpl) ServiceAccount() (string, error) {
	return "gae_service_account@example.com", nil
}

func (gi *giImpl) VersionID() string {
	return curGID(gi.c).versionID
}

func (gi *giImpl) RequestID() string {
	return curGID(gi.c).requestID
}

func (gi *giImpl) GetTestable() info.Testable {
	return gi
}

func (gi *giImpl) SetVersionID(v string) context.Context {
	return useGID(gi.c, func(mod *globalInfoData) {
		mod.versionID = v
	})
}

func (gi *giImpl) SetRequestID(v string) context.Context {
	return useGID(gi.c, func(mod *globalInfoData) {
		mod.requestID = v
	})
}
