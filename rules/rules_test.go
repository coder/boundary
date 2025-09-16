package rules

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluateRule(t *testing.T) {
	tcs := []struct{
		allowString string
		method string 
		url string
	}{
		{
			allowString: "method=GET",
			method: "GET",
			url: "https://github.com",
		},
	}

	for _, tc := range tcs {
		rule, err := ParseRule(tc.allowString)
		require.Nil(t, err)

		engine := NewEngine([]Rule{ rule }, nil)
		result := engine.Evaluate(tc.method, tc.url)
		require.Truef(t, result.Allowed, "expected allow rule %s to match method %s and url %s", tc.allowString, tc.method, tc.url)
	}
}


