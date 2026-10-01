package profiler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCookiesDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Set-Cookie": {"_uetsid=ABCDEF"},
	}, []byte(""))
	require.Contains(t, matches, "Microsoft Advertising", "Could not get correct match")

	t.Run("headers", func(t *testing.T) {
		got := wappalyzer.Fingerprint(map[string][]string{
			"Set-Cookie": {
				"JSESSIONID=111; Path=/; HttpOnly",
				"XSRF-TOKEN=abc; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Path=/",
				"laravel_session=eyJ; Path=/",
			},
		}, []byte(""))
		require.Equal(t, map[string]struct{}{"Java": {}, "Laravel": {}, "PHP": {}}, got)
	})

	t.Run("fetch joined", func(t *testing.T) {
		// The fetch API joins Set-Cookie headers with ", ".
		got := wappalyzer.Fingerprint(map[string][]string{
			"Set-Cookie": {"XSRF-TOKEN=abc; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Path=/, laravel_session=eyJ; Path=/"},
		}, []byte(""))
		require.Equal(t, map[string]struct{}{"Laravel": {}, "PHP": {}}, got)
	})

	t.Run("attributes are not cookies", func(t *testing.T) {
		got := wappalyzer.Fingerprint(map[string][]string{
			"Set-Cookie": {"a=1; jsessionid=111; Path=/"},
		}, []byte(""))
		require.Empty(t, got)
	})
}

func TestHeadersDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Server": {"now"},
	}, []byte(""))

	require.Contains(t, matches, "Vercel", "Could not get correct match")
}

func TestBodyDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	t.Run("meta", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html>
<head>
<meta name="generator" content="mura cms 1">
</head>
</html>`))
		require.Contains(t, matches, "Mura CMS:1", "Could not get correct match")
	})

	t.Run("html-implied", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html data-ng-app="RbsChangeApp">
<head>
</head>
<body>
</body>
</html>`))
		require.Contains(t, matches, "AngularJS", "Could not get correct implied match")
		require.Contains(t, matches, "PHP", "Could not get correct implied match")
		require.Contains(t, matches, "Proximis Unified Commerce", "Could not get correct match")
	})
}

func TestUniqueFingerprints(t *testing.T) {
	fingerprints := NewUniqueFingerprints()
	fingerprints.SetIfNotExists("test", "", 100)
	require.Equal(t, map[string]struct{}{"test": {}}, fingerprints.GetValues(), "could not get correct values")

	t.Run("linear", func(t *testing.T) {
		fingerprints.SetIfNotExists("new", "2.3.5", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}}, fingerprints.GetValues(), "could not get correct values")

		fingerprints.SetIfNotExists("new", "", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}}, fingerprints.GetValues(), "could not get correct values")
	})

	t.Run("opposite", func(t *testing.T) {
		fingerprints.SetIfNotExists("another", "", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}, "another": {}}, fingerprints.GetValues(), "could not get correct values")

		fingerprints.SetIfNotExists("another", "2.3.5", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}, "another:2.3.5": {}}, fingerprints.GetValues(), "could not get correct values")
	})

	t.Run("confidence", func(t *testing.T) {
		f := NewUniqueFingerprints()
		f.SetIfNotExists("test", "", 0)
		require.Equal(t, map[string]struct{}{}, f.GetValues(), "could not get correct values")

		f.SetIfNotExists("test", "2.36.4", 100)
		require.Equal(t, map[string]struct{}{"test:2.36.4": {}}, f.GetValues(), "could not get correct values")
	})
}
