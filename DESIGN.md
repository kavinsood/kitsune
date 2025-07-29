Here are my notes on the design and architecture for Kitsune.

### The Big Idea: Pre-Compiled Data

My main goal was to build a simple, tough, and fast library with a data pipeline I could trust.

The whole system is built on one core principle: I wanted to completely separate the runtime logic from all the messy, inconsistent fingerprint data out there.

To do this, I decided to use a pre-compiled, canonical data file (`fingerprints_data.json`) that gets checked directly into the repository. This makes our builds totally reproducible and fast since there are zero network calls at runtime for fingerprint data. The library just starts up instantly with a clean, validated dataset.

I made this happen by:

  * **Moving all the cleanup offline.** I created a separate updater tool that handles all the annoying work of parsing weird schemas. The main library doesn't have to deal with any of that.
  * **Failing fast.** Before any data gets committed, the pipeline tries to compile every single regex. If even one of them is bad, the whole process stops. This guarantees the data will work with Go's engine.

-----

### How the Data Pipeline Works (`cmd/update-fingerprints`)

I built a pipeline in Go to create that `fingerprints_data.json` file. I decided that updating the data should be a manual task for a developer, not some fragile CI job. This way, a human always reviews the changes with a `git diff` before they're committed.

Here's how it works when I run `go run ./cmd/update-fingerprints/main.go`:

1.  **Fetch:** It grabs the latest Wappalyzer extension `.xpi` file from Mozilla. I decided to use this as the single source of truth instead of trying to pull from multiple places. The tool just reads the archive in memory and merges all the `technologies/*.json` files.

2.  **Normalize:** This is where the magic happens. Wappalyzer's data can be a bit loose (like a field being a string *or* an array). My tool forces everything into the strict Go types I need at runtime. For example, if it sees a single string pattern, it just turns it into an array with one item.

3.  **Lint:** As a final check, the tool tries to compile every single regex. If they all work, it writes the final `fingerprints_data.json` and `categories_data.json` files. If anything fails, it stops.

-----

### The Library's Runtime Architecture

I designed the runtime to be fast and correct.

1.  **Concurrent Scanning:** The main analysis function starts by kicking off a bunch of goroutines to fetch everything it needs at the same time—the main page content, `robots.txt`, DNS records, and linked assets like JS and CSS. This really cuts down on the total analysis time by overlapping all the network I/O.

2.  **Flexible DOM Matching:** I implemented a flexible and pragmatic DOM matching engine. While it doesn't support every possible permutation found in the wild, it goes beyond simple existence checks. It uses CSS selectors to find elements and can then apply additional checks for specific **text content** or **attribute values**. This provides a powerful way to fingerprint technologies based on DOM structure without the overhead of a full browser rendering engine.

3.  **TLS Certificate Analysis:** Getting the TLS certificate issuer is a great fingerprinting signal. To do this without compromising security, I'm using a custom `http.Client`. Its `Transport` has a `VerifyConnection` callback, which lets me intercept the certificate chain during the TLS handshake.

4.  **Security & SSRF Protection:** To protect the server from Server-Side Request Forgery (SSRF) attacks, all incoming URLs for analysis are validated through a robust security library. This ensures that the server can only make requests to valid, public-facing internet hosts, preventing it from being tricked into accessing internal network resources.
