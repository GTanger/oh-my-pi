import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
	computeSha256,
	isDataUri,
	looksLikeBase64Blob,
	parseDataUri,
	sanitizeContent,
	scrubLiveCredentials,
	shannonEntropy,
	storeBlob,
	stripInjectedMemoryTags,
} from "@oh-my-pi/pi-mnemopi/core/content-sanitizer";

const ORIGINAL_BLOB_DIR = process.env.MNEMOPI_BLOB_DIR;

afterEach(() => {
	if (ORIGINAL_BLOB_DIR === undefined) {
		delete process.env.MNEMOPI_BLOB_DIR;
	} else {
		process.env.MNEMOPI_BLOB_DIR = ORIGINAL_BLOB_DIR;
	}
});

function useTempBlobDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "mnemopi-blobs-"));
	process.env.MNEMOPI_BLOB_DIR = join(dir, "blobs");
	return process.env.MNEMOPI_BLOB_DIR;
}

describe("content sanitizer data URI parsing", () => {
	it("detects data URI prefixes only", () => {
		expect(isDataUri("data:image/png;base64,iVBORw0KGgo=")).toBe(true);
		expect(isDataUri("data:text/plain;base64,SGVsbG8=")).toBe(true);
		expect(isDataUri("Hello world")).toBe(false);
		expect(isDataUri("just some text")).toBe(false);
	});

	it("parses base64 data URIs with explicit and default mime types", () => {
		const pngDot = Buffer.from(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])).toString("base64");
		expect(parseDataUri(`data:image/png;base64,${pngDot}`)).toEqual([
			"image/png",
			Buffer.from(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
		]);
		expect(parseDataUri("data:;base64,SGVsbG8=")).toEqual(["application/octet-stream", Buffer.from("Hello")]);
	});

	it("rejects invalid base64 and missing schemes", () => {
		expect(parseDataUri("data:image/png;base64,!!!not-valid!!!")).toBeNull();
		expect(parseDataUri("just text")).toBeNull();
	});
});

describe("content sanitizer entropy heuristic", () => {
	it("separates uniform random-looking text from prose and repeated characters", () => {
		const uniform = "abcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(2000);
		const prose = "hello world this is normal english text with common letters and patterns ".repeat(1000);
		const repeated = "aaaaa".repeat(10000);

		expect(shannonEntropy(uniform)).toBeGreaterThan(5.5);
		expect(shannonEntropy(prose)).toBeLessThan(5.0);
		expect(shannonEntropy(repeated)).toBeLessThan(0.1);
		expect(shannonEntropy("")).toBe(0.0);
	});

	it("flags large high-entropy base64-like payloads only", () => {
		const raw = Buffer.allocUnsafe(150_000);
		for (let i = 0; i < raw.length; i += 1) raw[i] = i & 0xff;
		const b64 = raw.toString("base64");
		const code = "def foo():\n    return 42\n".repeat(20000);

		expect(looksLikeBase64Blob(b64)).toBe(true);
		expect(looksLikeBase64Blob(code)).toBe(false);
	});
});

describe("content sanitizer blob storage", () => {
	it("stores blobs by sha256 and is idempotent", () => {
		const blobRoot = useTempBlobDir();
		const data = Buffer.from("binary blob content for testing");
		const sha = storeBlob(data);
		const path = join(blobRoot, sha.slice(0, 2), sha.slice(0, 4), sha);
		const mtime = statSync(path).mtimeMs;

		expect(sha).toHaveLength(64);
		expect(computeSha256(data)).toBe(sha);
		expect(readFileSync(path)).toEqual(data);
		expect(storeBlob(data)).toBe(sha);
		expect(statSync(path).mtimeMs).toBe(mtime);
	});
});

describe("sanitize_content", () => {
	it("extracts data URIs with metadata", () => {
		useTempBlobDir();
		const raw = Buffer.from("\x89PNG header fake binary data for test", "binary");
		const result = sanitizeContent(`data:image/png;base64,${raw.toString("base64")}`);

		expect(result[0]).toContain("Binary content extracted");
		expect(result[0]).toContain("blob://sha256/");
		expect(result[1].extraction_reason).toBe("data_uri");
		expect(result[1].mime).toBe("image/png");
		expect(result[1].original_size).toBe(raw.length);
	});

	it("extracts content above the hard cap", () => {
		useTempBlobDir();
		const [sanitized, meta] = sanitizeContent("x".repeat(1_000_001));
		expect(sanitized).toContain("Large content extracted");
		expect(meta.extraction_reason).toBe("size_cap");
	});

	it("extracts high-entropy payloads but leaves large prose untouched", () => {
		useTempBlobDir();
		const raw = Buffer.allocUnsafe(150_000);
		for (let i = 0; i < raw.length; i += 1) raw[i] = (i * 31) & 0xff;
		const highEntropy = raw.toString("base64");
		const prose =
			"This is a normal paragraph of English text. It discusses various topics in a conversational tone. ".repeat(
				3000,
			);

		const [sanitized, meta] = sanitizeContent(highEntropy);
		expect(sanitized).toContain("Encoded content extracted");
		expect(meta.extraction_reason).toBe("high_entropy");
		expect(meta.entropy).toBeGreaterThan(5.0);
		expect(sanitizeContent(prose)).toEqual([prose, {}]);
	});
});

describe("sanitizeContent tag stripping and credential scrubbing", () => {
	it("strips injected prompt and memory tags", () => {
		const text = `
Header text
<system-reminder>
Sensitive injected prompt details
</system-reminder>

Middle content
<memories>
Recalled memory block
</memories>

<private>
User secret notes
</private>
Tail content
`;
		const { content, stripped } = stripInjectedMemoryTags(text);
		expect(stripped).toBe(true);
		expect(content).not.toContain("<system-reminder>");
		expect(content).not.toContain("Sensitive injected prompt details");
		expect(content).not.toContain("<memories>");
		expect(content).not.toContain("<private>");
		expect(content).toContain("Header text");
		expect(content).toContain("Middle content");
		expect(content).toContain("Tail content");

		const [sanitized, meta] = sanitizeContent(text);
		expect(meta.stripped_tags).toBe(true);
		expect(sanitized).toBe(content);
	});

	it("scrubs live credentials and tracks matched types", () => {
		const pemHeader = `-----BEGIN ${"RSA PRIVATE"} KEY-----`;
		const pemFooter = `-----END ${"RSA PRIVATE"} KEY-----`;
		const pemKey = `${pemHeader}\nMIIEowIBAAKCAQEA0Y1+exampleFakeKeyMaterialForTestingOnly...\n${pemFooter}`;
		const sample = [
			pemKey,
			`API key: ${"sk-proj"}-1234567890abcdefghijklmnopqrstuvwxyz`,
			`GitHub: ${"ghp"}_1234567890abcdefghijklmnopqrstuvwxyz1234`,
			`Google: ${"AIzaSy"}A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q`,
			`AWS: ${"AKIA"}1234567890ABCDEF`,
			`Slack: ${"xox" + "b"}-12345678-abcdefghijklmnop`,
			`GitLab: ${"glpat"}-1234567890abcdefghij`,
			`Auth: Authorization: Bearer ${"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}`,
			`DB: https://admin:${"s3cr3tPass"}@db.internal:5432/app`,
		].join("\n");

		const { content, matchedTypes } = scrubLiveCredentials(sample);
		expect(matchedTypes).toEqual([
			"pem_private_key",
			"openai_anthropic_key",
			"github_pat",
			"google_api_key",
			"aws_access_key",
			"slack_or_gitlab_token",
			"auth_bearer_basic",
			"basic_auth_url",
		]);
		expect(content).toContain("[REDACTED_PRIVATE_KEY]");
		expect(content).toContain("API key: [REDACTED_API_KEY]");
		expect(content).toContain("GitHub: [REDACTED_GITHUB_TOKEN]");
		expect(content).toContain("Google: [REDACTED_GOOGLE_KEY]");
		expect(content).toContain("AWS: [REDACTED_AWS_KEY]");
		expect(content).toContain("Slack: [REDACTED_TOKEN]");
		expect(content).toContain("GitLab: [REDACTED_TOKEN]");
		expect(content).toContain("Auth: Authorization: Bearer [REDACTED_AUTH]");
		expect(content).toContain("DB: https://admin:[REDACTED_PASSWORD]@db.internal:5432/app");

		const [sanitized, meta] = sanitizeContent(sample);
		expect(meta.redacted_secrets).toEqual(matchedTypes);
		expect(sanitized).toBe(content);
	});

	it("preserves benign text, URLs, and documentation placeholders", () => {
		const benign = [
			"Documentation placeholder: AKIAIOSFODNN7EXAMPLE",
			"Example OpenAI key: sk-placeholder",
			"Config template: API_KEY=YOUR_API_KEY_HERE",
			"Public website: https://example.com/api/v1/resource",
			"Regular text discussing authentication patterns.",
		].join("\n");

		const { content: strippedText, stripped } = stripInjectedMemoryTags(benign);
		expect(stripped).toBe(false);
		expect(strippedText).toBe(benign);

		const { content: scrubbedText, matchedTypes } = scrubLiveCredentials(benign);
		expect(matchedTypes).toHaveLength(0);
		expect(scrubbedText).toBe(benign);

		const [sanitized, meta] = sanitizeContent(benign);
		expect(sanitized).toBe(benign);
		expect(meta).toEqual({});
	});

	it("handles nested/unclosed injected tags, unclosed PEM keys, and scrubs before blob extraction", () => {
		useTempBlobDir();
		const nested =
			"Before\n<private>outer <private>inner</private> leaked</private>\n<system-reminder>truncated tail";
		const strippedRes = stripInjectedMemoryTags(nested);
		expect(strippedRes.stripped).toBe(true);
		expect(strippedRes.content).toBe("Before");

		const unclosedPem = `Key:\n-----BEGIN ${"ENCRYPTED PRIVATE"} KEY-----\nMIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQISecretMaterial`;
		const scrubbedPem = scrubLiveCredentials(unclosedPem);
		expect(scrubbedPem.matchedTypes).toEqual(["pem_private_key"]);
		expect(scrubbedPem.content).toBe("Key:\n[REDACTED_PRIVATE_KEY]");
		expect(scrubbedPem.content).not.toContain("MIIFDj");
	});
});
