package abstract

import (
	"context"
	"testing"

	"github.com/pydio/cells/v5/common"
	"github.com/pydio/cells/v5/common/auth/claim"
	"github.com/pydio/cells/v5/common/nodes"
	"github.com/pydio/cells/v5/common/proto/tree"
	"github.com/pydio/cells/v5/common/utils/cache/gocache"
	cache_helper "github.com/pydio/cells/v5/common/utils/cache/helper"
)

type recoveringSources struct {
	nodes.SourcesPool
	sources map[string]nodes.LoadedSource
	recover bool
	loads   int
}

func (p *recoveringSources) GetDataSources() map[string]nodes.LoadedSource {
	result := make(map[string]nodes.LoadedSource)
	for key, source := range p.sources {
		result[key] = source
	}
	return result
}

func (p *recoveringSources) LoadDataSources() {
	p.loads++
	if p.recover {
		p.sources["personal"] = nodes.LoadedSource{}
	}
}

func TestVirtualDatasourceRecovery(t *testing.T) {
	cache_helper.SetStaticResolver("pm://", &gocache.URLOpener{})
	ctx := context.Background()
	cache := cache_helper.MustResolveCache(ctx, common.CacheTypeLocal, cacheConfig)
	_ = cache.Set("###virtual-nodes###", []*tree.Node{})
	_ = cache.Set("###login-lower###", false)
	manager := &virtualNodesManager{}
	script := "SplitMode = true; DataSourceName = DataSources.personal; DataSourcePath = User.Name;"
	for _, tc := range []struct {
		name                      string
		present, recover, invalid bool
		empty                     bool
		wantLoads                 int
		wantError                 bool
	}{
		{"partially loaded pool recovers", false, true, false, false, 1, false},
		{"missing source fails after one retry", false, false, false, false, 1, true},
		{"ready pool is not reloaded", true, false, false, false, 0, false},
		{"invalid script is not retried", false, true, true, false, 0, true},
		{"empty pool recovers", false, true, false, true, 1, false},
		{"empty pool fails after one load", false, false, false, true, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := &recoveringSources{sources: map[string]nodes.LoadedSource{"common": {}}, recover: tc.recover}
			if tc.empty {
				delete(pool.sources, "common")
			}
			if tc.present {
				pool.sources["personal"] = nodes.LoadedSource{}
			}
			v := &tree.Node{MetaStore: map[string]string{"contentType": "text/javascript", "resolution": script}}
			if tc.invalid {
				v.MetaStore["resolution"] = "this is invalid javascript!"
			}
			resolved, err := manager.resolvePathWithClaims(ctx, v, claim.Claims{Name: "alice"}, pool)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError %v", err, tc.wantError)
			}
			if pool.loads != tc.wantLoads {
				t.Fatalf("loads = %d, want %d", pool.loads, tc.wantLoads)
			}
			if err != nil {
				if resolved != nil {
					t.Fatal("failed resolution returned a node")
				}
				return
			}
			if resolved.Path != "personal/alice" {
				t.Fatalf("path = %q", resolved.Path)
			}
			if resolved.GetStringMeta(common.MetaNamespaceDatasourceName) != "personal" || resolved.GetStringMeta(common.MetaNamespaceDatasourcePath) != "alice" {
				t.Fatal("resolved metadata does not match the user's datasource path")
			}
			other, err := manager.resolvePathWithClaims(ctx, v, claim.Claims{Name: "bob"}, pool)
			if err != nil || other.Path != "personal/bob" {
				t.Fatalf("second user resolution = %v, %v", other, err)
			}
			if pool.loads != tc.wantLoads {
				t.Fatal("ready pool was reloaded for second user")
			}
		})
	}
}
