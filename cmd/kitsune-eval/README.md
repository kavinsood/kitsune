# kitsune-eval

Measures how well kitsune detects techs, on two labeled sets of pages:

  * **corpus** (`corpus.txt`): 45 well-known sites, each with the few techs it is known for (53 in all). Pages are analyzed without their URL (`Fingerprint`): no DNS, and only the assets they link by absolute URL. The score is the expected techs found, plus how many techs are detected and which show up on more than 20% of the pages, which is a sign of noise.
  * **truth** (`truth.json`): 37 sites whose techs were checked by hand (340 in all), with the techs known to be falsely detected on them. Pages go through the full pipeline at their final URL, as the API does (`FingerprintWithURL`), with their DNS records and the scripts and stylesheets they link. The score is the expected techs found, the known false positives detected, and the detections that aren't labeled either way.

## Usage

From the root of the repository:

```sh
go run ./cmd/kitsune-eval                     # fetch what's missing, run both sets, score
go run ./cmd/kitsune-eval -tag before         # save the results as "before" (default: the git commit)
go run ./cmd/kitsune-eval -tag after -compare before
go run ./cmd/kitsune-eval diff before after   # compare two saved results
go run ./cmd/kitsune-eval fetch -refresh      # download a new snapshot
```

`-offline` never downloads, `-v` lists the requests the snapshot couldn't serve, and `-cache dir` uses another snapshot. A diff prints the change in each score and the techs gained (`+`) and lost (`-`) on each page, marked when they are expected or known false positives.

## The snapshot

The first run downloads the pages, their DNS records and every asset the engine requests while analyzing them into `cache/` (git-ignored, about 130 MB). That takes about a minute. Every later run is served from it, with no network access: assets the snapshot lacks are served as 404s, and their count is printed. Pages that failed to download are retried on the next run that isn't `-offline`.

```
cache/snapshot.json        when the snapshot was taken
cache/corpus/<host>.json   pages: the JSON records update-fingerprints -corpus reads
cache/truth/<id>.json      pages with their DNS records
cache/assets/              assets by URL (index.json) and their content
cache/results/<tag>.json   saved results
```

Results are saved with the snapshot they ran on, so `-refresh` keeps them, and a diff warns when two results come from different snapshots.

**Snapshot drift.** The labels describe the sites as they were when they were checked. Sites change: they switch frameworks, drop trackers and redesign. A snapshot is therefore only meaningful against itself. Compare builds on the same snapshot; never compare scores across snapshots as if they measured the build. The date of the snapshot is printed with every score, with a warning after 30 days. When you refresh, run the old build on the new snapshot first: any change from the old numbers is drift, and may call for updating the labels.

## Labels

`corpus.txt` has one site per line: the host, a space, and the expected techs separated by commas. `truth.json` has one site per line: `id`, `url`, `name`, `expected` and `false_positives`. Tech names are the fingerprint names, without versions. Add a site by adding a line; the next run downloads it.

## Importing old pages

`import` builds a snapshot from pages saved earlier: corpus pages as `<host>.json` records, and truth pages as saved by curl (`NN.meta` with "status url", `NN.hdr`, `NN.html`). Their assets and DNS records are downloaded on import, so they are as of the import.

```sh
go run ./cmd/kitsune-eval import -corpus old/corpus -truth old/truth -cache cmd/kitsune-eval/cache-old
go run ./cmd/kitsune-eval -offline -cache cmd/kitsune-eval/cache-old
```

## Related

`internal/profiler/corpus_bench_test.go` (`KITSUNE_CORPUS`) benchmarks the engine's speed on a few saved sites. This command measures accuracy.
