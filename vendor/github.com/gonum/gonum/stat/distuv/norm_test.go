// Copyright ©2014 The gonum Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package distuv

import (
	"fmt"
	"math"
	"testing"

	"github.com/gonum/gonum/floats"
)

// TestNormalProbs tests LogProb, Prob, CumProb, and Quantile
func TestNormalProbs(t *testing.T) {
	pts := []univariateProbPoint{
		{
			loc:     0,
			prob:    oneOverRoot2Pi,
			cumProb: 0.5,
			logProb: -0.91893853320467274178032973640561763986139747363778341281715,
		},
		{
			loc:     -1,
			prob:    0.2419707245191433497978301929355606548286719707374350254875550842811000635700832945083112946939424047,
			cumProb: 0.158655253931457051414767454367962077522087033273395609012605,
			logProb: math.Log(0.2419707245191433497978301929355606548286719707374350254875550842811000635700832945083112946939424047),
		},
		{
			loc:     1,
			prob:    0.2419707245191433497978301929355606548286719707374350254875550842811000635700832945083112946939424047,
			cumProb: 0.841344746068542948585232545632037922477912966726604390987394,
			logProb: math.Log(0.2419707245191433497978301929355606548286719707374350254875550842811000635700832945083112946939424047),
		},
		{
			loc:     -7,
			prob:    9.134720408364593342868613916794233023000190834851937054490546361277622761970225469305158915808284566e-12,
			cumProb: 1.279812543885835004383623690780832998032844154198717929e-12,
			logProb: math.Log(9.134720408364593342868613916794233023000190834851937054490546361277622761970225469305158915808284566e-12),
		},
		{
			loc:     7,
			prob:    9.134720408364593342868613916794233023000190834851937054490546361277622761970225469305158915808284566e-12,
			cumProb: 0.99999999999872018745611416499561637630921916700196715584580,
			logProb: math.Log(9.134720408364593342868613916794233023000190834851937054490546361277622761970225469305158915808284566e-12),
		},
	}
	testDistributionProbs(t, Normal{Mu: 0, Sigma: 1}, "normal", pts)

	pts = []univariateProbPoint{
		{
			loc:     2,
			prob:    0.07978845608028653558798921198687637369517172623298693153318516593413158517986036770025046678146138729,
			cumProb: 0.5,
			logProb: math.Log(0.07978845608028653558798921198687637369517172623298693153318516593413158517986036770025046678146138729),
		},
		{
			loc:     -3,
			prob:    0.04839414490382866995956603858711213096573439414748700509751101685622001271401665890166225893878848095,
			cumProb: 0.158655253931457051414767454367962077522087033273395609012605,
			logProb: math.Log(0.04839414490382866995956603858711213096573439414748700509751101685622001271401665890166225893878848095),
		},
		{
			loc:     7,
			prob:    0.04839414490382866995956603858711213096573439414748700509751101685622001271401665890166225893878848095,
			cumProb: 0.841344746068542948585232545632037922477912966726604390987394,
			logProb: math.Log(0.04839414490382866995956603858711213096573439414748700509751101685622001271401665890166225893878848095),
		},
		{
			loc:     -33,
			prob:    1.826944081672918668573722783358846604600038166970387410898109272255524552394045093861031783161656913e-12,
			cumProb: 1.279812543885835004383623690780832998032844154198717929e-12,
			logProb: math.Log(1.826944081672918668573722783358846604600038166970387410898109272255524552394045093861031783161656913e-12),
		},
		{
			loc:     37,
			prob:    1.826944081672918668573722783358846604600038166970387410898109272255524552394045093861031783161656913e-12,
			cumProb: 0.99999999999872018745611416499561637630921916700196715584580,
			logProb: math.Log(1.826944081672918668573722783358846604600038166970387410898109272255524552394045093861031783161656913e-12),
		},
	}
	testDistributionProbs(t, Normal{Mu: 2, Sigma: 5}, "normal", pts)
}

func TestNormFitPrior(t *testing.T) {
	testConjugateUpdate(t, func() ConjugateUpdater { return &Normal{Mu: -10, Sigma: 6} })
}

func TestNormScore(t *testing.T) {
	for _, test := range []*Normal{
		{
			Mu:    0,
			Sigma: 1,
		},
		{
			Mu:    0.32238,
			Sigma: 13.69,
		},
	} {
		testDerivParam(t, test)
	}
}

func TestNormalQuantile(t *testing.T) {
	// Values from https://www.johndcook.com/blog/normal_cdf_inverse/
	p := []float64{
		0.0000001,
		0.00001,
		0.001,
		0.05,
		0.15,
		0.25,
		0.35,
		0.45,
		0.55,
		0.65,
		0.75,
		0.85,
		0.95,
		0.999,
		0.99999,
		0.9999999,
	}
	ans := []float64{
		-5.199337582187471,
		-4.264890793922602,
		-3.090232306167813,
		-1.6448536269514729,
		-1.0364333894937896,
		-0.6744897501960817,
		-0.38532046640756773,
		-0.12566134685507402,
		0.12566134685507402,
		0.38532046640756773,
		0.6744897501960817,
		1.0364333894937896,
		1.6448536269514729,
		3.090232306167813,
		4.264890793922602,
		5.199337582187471,
	}
	for i, v := range p {
		got := UnitNormal.Quantile(v)
		fmt.Println(math.Abs(got - ans[i]))
		if !floats.EqualWithinAbsOrRel(got, ans[i], 1e-10, 1e-10) {
			t.Errorf("Quantile mismatch. Case %d, want: %v, got: %v", i, ans[i], got)
		}
	}
}

func BenchmarkNormalQuantile(b *testing.B) {
	n := Normal{Mu: 2, Sigma: 3.1}
	ps := make([]float64, 1000) // ensure there are small values
	floats.Span(ps, 0, 1)
	for i := 0; i < b.N; i++ {
		for _, v := range ps {
			x := n.Quantile(v)
			_ = x
		}
	}
}
