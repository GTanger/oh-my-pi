import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const SIZE_HARD_CAP = 1_000_000;
export const SIZE_BASE64_CHECK = 100_000;
export const ENTROPY_THRESHOLD = 5.0;

const DATA_URI_RE = /^data:(?<mime>[^;]+)?(?:;base64)?,(?<payload>.*)/i;
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export interface BlobMetadata {
	blob_ref?: string;
	original_size?: number;
	mime?: string;
	extraction_reason?: "data_uri" | "size_cap" | "high_entropy";
	entropy?: number;
}

export interface SanitizeMetadata {
	blob_ref?: string;
	extraction_reason?: "data_uri" | "size_cap" | "high_entropy";
	original_size?: number;
	sha256?: string;
	mime?: string;
	entropy?: number;
	stripped_tags?: boolean;
	redacted_secrets?: string[];
}

export function blobRoot(env: NodeJS.ProcessEnv = process.env): string {
	return env.MNEMOPI_BLOB_DIR && env.MNEMOPI_BLOB_DIR.length > 0
		? env.MNEMOPI_BLOB_DIR
		: join(homedir(), ".hermes", "mnemopi", "blobs");
}

export function computeSha256(data: Uint8Array | string): string {
	return Bun.SHA256.hash(data, "hex");
}

export function isDataUri(content: string): boolean {
	return content.startsWith("data:");
}

export function parseDataUri(content: string): [mimeType: string, raw: Buffer] | null {
	const match = DATA_URI_RE.exec(content);
	if (match?.groups === undefined) return null;

	const mimeType = match.groups.mime ?? "application/octet-stream";
	const payload = match.groups.payload ?? "";
	if (!isValidBase64(payload)) return null;

	return [mimeType, Buffer.from(payload, "base64")];
}

export function shannonEntropy(text: string): number {
	if (text.length === 0) return 0.0;

	const counts = new Map<string, number>();
	for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1);

	let entropy = 0.0;
	for (const count of counts.values()) {
		const p = count / text.length;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

export function looksLikeBase64Blob(content: string): boolean {
	if (content.length < SIZE_BASE64_CHECK) return false;
	return shannonEntropy(content) > ENTROPY_THRESHOLD;
}

export function storeBlob(rawBytes: Uint8Array): string {
	const sha256 = computeSha256(rawBytes);
	const blobDir = join(blobRoot(), sha256.slice(0, 2), sha256.slice(0, 4));
	mkdirSync(blobDir, { recursive: true });
	const blobPath = join(blobDir, sha256);
	if (!existsSync(blobPath)) writeFileSync(blobPath, rawBytes);
	return sha256;
}
const INJECTED_TAG_NAMES = [
	"memories",
	"mental_models",
	"hindsight_memories",
	"relevant_memories",
	"system-reminder",
	"private",
];

const INJECTED_TAGS_RE = new RegExp(
	INJECTED_TAG_NAMES.map(tag => `<${tag}\\b[^>]*>(?:(?!(?:<${tag}\\b|<\\/${tag}>))[\\s\\S])*?<\\/${tag}>`).join("|"),
	"gi",
);

const UNCLOSED_INJECTED_TAG_RE = new RegExp(`<(?:${INJECTED_TAG_NAMES.join("|")})\\b[^>]*>[\\s\\S]*$`, "i");

const ORPHAN_CLOSING_TAG_RE = new RegExp(`<\\/(?:${INJECTED_TAG_NAMES.join("|")})\\s*>`, "gi");

export function stripInjectedMemoryTags(content: string): { content: string; stripped: boolean } {
	let stripped = false;
	let current = content;
	while (true) {
		let passMatched = false;
		current = current.replace(INJECTED_TAGS_RE, () => {
			passMatched = true;
			stripped = true;
			return "";
		});
		if (!passMatched) break;
	}

	const withoutUnclosed = current.replace(UNCLOSED_INJECTED_TAG_RE, () => {
		stripped = true;
		return "";
	});
	const withoutOrphan = withoutUnclosed.replace(ORPHAN_CLOSING_TAG_RE, () => {
		stripped = true;
		return "";
	});

	if (!stripped) {
		return { content, stripped: false };
	}

	const cleaned = withoutOrphan.replace(/\n{3,}/g, "\n\n").trim();
	return { content: cleaned, stripped: true };
}

const CREDENTIAL_RULES: Array<{
	type: string;
	pattern: RegExp;
	replacement: string;
}> = [
	{
		type: "pem_private_key",
		pattern:
			/-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\r\n\t -]*/g,
		replacement: "[REDACTED_PRIVATE_KEY]",
	},
	{
		type: "openai_anthropic_key",
		pattern: /\bsk-(?:proj|ant-api\d*|live)-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{36,}\b/g,
		replacement: "[REDACTED_API_KEY]",
	},
	{
		type: "github_pat",
		pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g,
		replacement: "[REDACTED_GITHUB_TOKEN]",
	},
	{
		type: "google_api_key",
		pattern: /\bAIzaSy[A-Za-z0-9_-]{33}\b/g,
		replacement: "[REDACTED_GOOGLE_KEY]",
	},
	{
		type: "aws_access_key",
		pattern: /\bAKIA(?!IOSFODNN7EXAMPLE\b)[0-9A-Z]{16}\b/g,
		replacement: "[REDACTED_AWS_KEY]",
	},
	{
		type: "slack_or_gitlab_token",
		pattern: /\b(?:xox[baprs]-[0-9]{8,}-[0-9A-Za-z-]{16,}|glpat-[A-Za-z0-9_-]{20,})\b/g,
		replacement: "[REDACTED_TOKEN]",
	},
	{
		type: "auth_bearer_basic",
		pattern: /\b(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s"',;]{8,}/gi,
		replacement: "$1[REDACTED_AUTH]",
	},
	{
		type: "basic_auth_url",
		pattern: /\b(https?:\/\/[^/\s:@]+:)([^@\s/]{6,})(@[^\s"'/]+)/gi,
		replacement: "$1[REDACTED_PASSWORD]$3",
	},
];

export function scrubLiveCredentials(content: string): { content: string; matchedTypes: string[] } {
	let current = content;
	const matchedTypes: string[] = [];

	for (const rule of CREDENTIAL_RULES) {
		rule.pattern.lastIndex = 0;
		let matched = false;
		current = current.replace(rule.pattern, (...args) => {
			matched = true;
			if (rule.replacement === "$1[REDACTED_AUTH]") {
				return `${args[1] as string}[REDACTED_AUTH]`;
			}
			if (rule.replacement === "$1[REDACTED_PASSWORD]$3") {
				return `${args[1] as string}[REDACTED_PASSWORD]${args[3] as string}`;
			}
			return rule.replacement;
		});
		if (matched) matchedTypes.push(rule.type);
	}

	return { content: current, matchedTypes };
}

export function sanitizeContent(content: string): [sanitizedContent: string, meta: SanitizeMetadata] {
	if (isDataUri(content)) {
		const parsed = parseDataUri(content);
		if (parsed !== null) {
			const [mimeType, rawBytes] = parsed;
			const sha256 = storeBlob(rawBytes);
			const blobRef = `blob://sha256/${sha256}`;
			return [
				`[Binary content extracted: ${mimeType}, ${rawBytes.length.toLocaleString("en-US")} bytes → ${blobRef}]`,
				{
					blob_ref: blobRef,
					original_size: rawBytes.length,
					mime: mimeType,
					extraction_reason: "data_uri",
				},
			];
		}
	}

	const meta: SanitizeMetadata = {};
	let text = content;

	const tagResult = stripInjectedMemoryTags(text);
	if (tagResult.stripped) {
		text = tagResult.content;
		meta.stripped_tags = true;
	}

	const credResult = scrubLiveCredentials(text);
	if (credResult.matchedTypes.length > 0) {
		text = credResult.content;
		meta.redacted_secrets = credResult.matchedTypes;
	}

	const textByteSize = Buffer.byteLength(text, "utf8");
	if (textByteSize > SIZE_HARD_CAP) {
		const rawBytes = Buffer.from(text, "utf8");
		const sha256 = storeBlob(rawBytes);
		const blobRef = `blob://sha256/${sha256}`;
		return [
			`[Large content extracted: ${textByteSize.toLocaleString("en-US")} bytes → ${blobRef}]`,
			{
				...meta,
				blob_ref: blobRef,
				original_size: textByteSize,
				extraction_reason: "size_cap",
			},
		];
	}

	if (textByteSize > SIZE_BASE64_CHECK && looksLikeBase64Blob(text)) {
		const rawBytes = Buffer.from(text, "utf8");
		const sha256 = storeBlob(rawBytes);
		const entropy = Math.round(shannonEntropy(text) * 100) / 100;
		const blobRef = `blob://sha256/${sha256}`;
		return [
			`[Encoded content extracted: ${textByteSize.toLocaleString("en-US")} bytes, entropy ${entropy.toFixed(1)} bits/char → ${blobRef}]`,
			{
				...meta,
				blob_ref: blobRef,
				original_size: textByteSize,
				entropy,
				extraction_reason: "high_entropy",
			},
		];
	}

	return [text, meta];
}
function isValidBase64(payload: string): boolean {
	if (payload.length % 4 !== 0) return false;
	if (!BASE64_RE.test(payload)) return false;
	try {
		Buffer.from(payload, "base64");
		return true;
	} catch {
		return false;
	}
}
