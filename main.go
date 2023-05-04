package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	bundlev1 "github.com/zntrio/harp/v2/api/gen/go/harp/bundle/v1"
	"github.com/zntrio/harp/v2/pkg/bundle/pipeline"
	"github.com/zntrio/harp/v2/pkg/bundle/secret"
	"github.com/zntrio/harp/v2/pkg/sdk/log"
)

var (
	privateKeyPattern = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`)
	datadogAppKeyPatttern = regexp.MustCompile(`\b([a-zA-Z-0-9]{40})\b`)
	datadogAPIKeyPattern = regexp.MustCompile(`\b([a-zA-Z-0-9]{32})\b`)
	googleOAuthClientIDPattern = regexp.MustCompile(`(i?)[0-9]*-[0-9a-z]*.apps.googleusercontent.com`)
	awsClientKeyPattern     = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`)
	awsClientSecretPattern = regexp.MustCompile(`[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}`)
	awsFalsePositiveSecretCheck = regexp.MustCompile(`[a-f0-9]{40}`)
	githubKeyPattern = regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`)
	genericLowercaseAlpha = regexp.MustCompile(`\b[a-z]+\b`)
	genericUppercaseAlpha = regexp.MustCompile(`\b[A-Z]+\b`)
	genericAlphaNumeric = regexp.MustCompile(`\b[a-zA-Z0-9]+\b`)
	genericPrintableASCII = regexp.MustCompile(`\b[\x21-\x7e]{8,64}\b`)
	genericHexEncoded = regexp.MustCompile(`\b[A-Fa-f0-9x]{6,99}\b`) 
	genericBcryptHash = regexp.MustCompile(`\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9\.\/]{53}`)
)

type hit struct {
	Path string `json:"path"`
	Key string `json:"key"`
	Matchers []string `json:"matchers"`
}

func main() {
	var (
		// Initialize an execution context
		ctx = context.Background()
	)

	// Initialize auditor hit channel
	hits := make(chan hit)
	eg, egCtx := errgroup.WithContext(ctx)
	
	eg.Go(func() error {
		stats := []any{}

		// Process each hit
		for h := range hits {
			stats = append(stats, h)
		}

		// Dump JSON
		if err := json.NewEncoder(os.Stdout).Encode(stats); err != nil {
			return fmt.Errorf("unable to encode audit stats: %w", err)
		}

		return nil
	})

	// Run the pipeline
	if err := pipeline.Run(egCtx,
		pipeline.KVProcessor(secretAuditor(hits)),
		pipeline.OutputDisabled(),
	); err != nil {
		log.For(egCtx).Fatal("unable to process bundle", zap.Error(err))
	}
	close(hits)

	if err := eg.Wait(); err != nil {
		log.For(ctx).Fatal("unable to audit given bundle", zap.Error(err))
	}
}

// -----------------------------------------------------------------------------

// get EntropyInt will calculate the entrophy based upon Shannon Entropy
func getEntropyInt(s string) float64 {
	//Shannon Entropy calculation
	m := map[rune]float64{}
	for _, r := range s {
		m[r]++
	}
	var hm float64
	for _, c := range m {
		hm += c * math.Log2(c)
	}
	l := float64(len(s))
	res := math.Log2(l) - hm/l

	return res
}

// -----------------------------------------------------------------------------

func secretAuditor(stats chan hit) func(pipeline.Context, *bundlev1.KV) error {
	return func(ctx pipeline.Context, kv *bundlev1.KV) error {
		// Try to unpack secret
		var out string
		if err := secret.Unpack(kv.Value, &out); err != nil {
			return fmt.Errorf("unable to unpack the secret value: %w", err)
		}

		matchers := []string{}
		detectors := map[string]func() bool{
			"private_key": func() bool { return privateKeyPattern.MatchString(out)},
			"dd_api_key": func() bool { return datadogAPIKeyPattern.MatchString(out)},
			"dd_app_key": func() bool { return datadogAppKeyPatttern.MatchString(out)},
			"google_oauth_client_id": func() bool { return googleOAuthClientIDPattern.MatchString(out)},
			"aws_client_key": func() bool { return awsClientKeyPattern.MatchString(out)},
			"aws_client_secret": func() bool { return awsClientSecretPattern.MatchString(out) && !awsFalsePositiveSecretCheck.MatchString(out) },
			"github_token": func() bool { return githubKeyPattern.MatchString(out) },
			"generic_lowercase_alpha": func () bool { return genericLowercaseAlpha.MatchString(out) },
			"generic_uppercase_alpha": func () bool { return genericUppercaseAlpha.MatchString(out) },
			"generic_alphanum": func () bool { return genericAlphaNumeric.MatchString(out) },
			"generic_printable_ascii": func () bool { return genericPrintableASCII.MatchString(out) },
			"generic_hex": func () bool { return genericHexEncoded.MatchString(out)	},
			"generic_bcrypt_hash": func() bool { return genericBcryptHash.MatchString(out) },
		}
		for k, detector := range detectors {
			if detector() {
				matchers = append(matchers, k)
			}
		}

		// Compute entropy
		entropy := getEntropyInt(out)
		switch {
		case entropy < 4:
			matchers = append(matchers, "entropy_low")
		case entropy >= 4 && entropy < 5:
			matchers = append(matchers, "entropy_medium")
		case entropy >= 5:
			matchers = append(matchers, "entropy_high")
		}

		stats <- hit{Path: ctx.GetPackage().Name, Key: kv.Key, Matchers: matchers}

		// No error
		return nil
	}
}
