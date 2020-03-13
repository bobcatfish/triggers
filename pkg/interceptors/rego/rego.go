/*
Copyright 2019 The Tekton Authors

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

package rego

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/open-policy-agent/opa/rego"
	"github.com/tektoncd/triggers/pkg/interceptors"
	"go.uber.org/zap"

	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1alpha1"
)

type Interceptor struct {
	Logger *zap.SugaredLogger
	Rego   *triggersv1.RegoInterceptor
}

func NewInterceptor(rego *triggersv1.RegoInterceptor, l *zap.SugaredLogger) interceptors.Interceptor {
	return &Interceptor{
		Logger: l,
		Rego:   rego,
	}
}

func (w *Interceptor) ExecuteTrigger(request *http.Request) (*http.Response, error) {
	// TODO: do something with http request before calling this jeez
	var payload []byte

	if request.Body != nil {
		defer request.Body.Close()
		var err error
		payload, err = ioutil.ReadAll(request.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading request body: %w", err)
		}
	}

	var bodyAsMap map[string]interface{}
	err := json.Unmarshal(payload, &bodyAsMap)

	if err != nil {
		return nil, fmt.Errorf("error making the evaluation context: %w", err)
	}

	input := map[string]interface{}{
		"body":   bodyAsMap,
		"header": request.Header,
	}

	w.Logger.Infof("poop rego executing: %v", input)

	// TODO: use prepared queries
	rs, err := rego.New(
		rego.Module("trigger.rego", w.Rego.Source),
		rego.Query("filter := data.main.filter; overlay := data.main.overlay"),
		rego.Input(input)).Eval(request.Context())
	w.Logger.Infof("poop rego returned: %v err: %v", rs, err)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate trigger policy: %v", err)
	}

	// TODO: how to distinguish between "filter says no" and actual runtime error.
	//  - undefined happens when filter fails
	if len(rs) == 0 {
		return nil, fmt.Errorf("filter or overlay are undefined")
	}

	if _, ok := rs[0].Bindings["filter"].(bool); !ok {
		return nil, fmt.Errorf("filter says no")
	}

	overlay, ok := rs[0].Bindings["overlay"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected overlay type: %T", rs[0].Bindings["overlay"])
	}

	merged := mergeObjects(bodyAsMap, overlay)

	bs, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged data: %v", err)
	}

	// TODO: deal w/ overlays
	return &http.Response{
		Header: request.Header,
		Body:   ioutil.NopCloser(bytes.NewBuffer(bs)),
	}, nil
}

func mergeObjects(a, b map[string]interface{}) map[string]interface{} {
	for k := range b {
		if av, ok := a[k].(map[string]interface{}); ok {
			if bv, ok := b[k].(map[string]interface{}); ok {
				a[k] = mergeObjects(av, bv)
				continue
			}
		}
		a[k] = b[k]
	}
	return a
}
