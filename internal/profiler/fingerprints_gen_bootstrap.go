//go:build kitsune_gen_bootstrap

package profiler

// Stand-ins for the data in zz_generated_fingerprints.go, so kitsune-gen can
// be built with -tags kitsune_gen_bootstrap even when the generated file is
// missing or doesn't compile. See fingerprints_data.go.

var generatedCategories map[int]categoryItem

const generatedFingerprints, generatedFingerprintText = "", ""
