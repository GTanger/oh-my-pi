const RECALL_TOKEN_RE = /[a-z0-9][a-z0-9_.:/+-]*/g;
const CJK_RE = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u;
export const CJK_RUN_RE = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]{2,}/gu;
const NON_CJK_TOKEN_RUN_RE = /[a-z0-9][a-z0-9_.-]*/gi;
export const CJK_PARTICLE_SPLIT_RE = /[的了嗎呢吧啊呀嘛和與及或對將把被從向由給為於並而但卻又也還只就才已曾讓跟]/u;
export const CJK_STOP_SEGMENTS: ReadonlySet<string> = new Set([
	"什麼",
	"什么",
	"如何",
	"怎麼",
	"怎么",
	"哪些",
	"哪個",
	"哪个",
	"為什麼",
	"为什么",
	"是否",
	"可以",
	"一個",
	"一个",
	"這個",
	"这个",
	"那個",
	"那个",
	"我們",
	"我们",
	"你們",
	"你们",
	"他們",
	"他们",
	"檢查",
	"检查",
	"查看",
	"查詢",
	"查询",
	"請問",
	"请问",
]);
const CJK_QUESTION_PREFIXES = ["請問", "请问", "關於", "关于", "檢查", "检查", "查看", "查詢", "查询"] as const;

export const FACT_MATCH_STOPWORDS = new Set([
	"a",
	"an",
	"and",
	"are",
	"as",
	"at",
	"be",
	"by",
	"can",
	"could",
	"did",
	"do",
	"does",
	"for",
	"from",
	"had",
	"has",
	"have",
	"how",
	"i",
	"in",
	"is",
	"it",
	"its",
	"me",
	"my",
	"of",
	"on",
	"or",
	"our",
	"related",
	"should",
	"that",
	"the",
	"their",
	"there",
	"this",
	"to",
	"totally",
	"unrelated",
	"use",
	"uses",
	"was",
	"we",
	"what",
	"when",
	"where",
	"which",
	"who",
	"why",
	"with",
	"you",
	"your",
]);

export const RECALL_SYNONYMS: Readonly<Record<string, readonly string[]>> = {
	branding: ["brand", "positioning", "identity", "wording"],
	preference: ["prefer", "prefers", "want", "wants", "reject", "rejects", "avoid", "grounded"],
	professional: ["software", "builder"],
	url: ["link", "profile"],
	current: ["now", "live", "latest"],
	feeling: ["feel", "feels"],
	imposter: ["self-doubt", "doubt", "insecure"],
};

export function isCjkChar(ch: string): boolean {
	return CJK_RE.test(ch);
}

export function hasCjk(text: string): boolean {
	return CJK_RE.test(text);
}

export const containsSpacelessCjk = hasCjk;

/** Endings that turn one form of a word into another: `backup`/`backups`, `deploy`/`deployment`. */
const WORD_FORM_ENDINGS: readonly string[] = ["s", "es", "d", "ed", "ing", "er", "ers", "ment", "ments"];
/** Endings that replace a final `e`: `cache`/`caching`, `create`/`creation`. */
const SILENT_E_ENDINGS: readonly string[] = ["ing", "ion", "ions"];
/** Endings that replace a final `y`: `story`/`stories`, `copy`/`copied`. */
const FINAL_Y_ENDINGS: readonly string[] = ["ies", "ied"];

/**
 * Weak match between two forms of one word, in either direction: the longer token is the shorter
 * one plus an inflectional or common derivational ending (`facts`/`fact`, `deploy`/`deployment`,
 * `caching`/`cache`, `stories`/`story`). The shorter token needs at least four characters. Any
 * other extension or fragment never matches, so `1password`, `password` and `passport` do not
 * find `pass`, and `redis` does not find `redistribution`. This is deliberately not a stemmer.
 */
export function matchesWordForm(left: string, right: string): boolean {
	const [shorter, longer] = left.length <= right.length ? [left, right] : [right, left];
	if (shorter.length < 4 || longer.length === shorter.length) return false;
	if (longer.startsWith(shorter) && WORD_FORM_ENDINGS.includes(longer.slice(shorter.length))) return true;
	const stem = shorter.slice(0, -1);
	if (!longer.startsWith(stem)) return false;
	const ending = longer.slice(stem.length);
	if (shorter.endsWith("e")) return SILENT_E_ENDINGS.includes(ending);
	if (shorter.endsWith("y")) return FINAL_Y_ENDINGS.includes(ending);
	return false;
}

export function recallTokens(text: string): string[] {
	RECALL_TOKEN_RE.lastIndex = 0;
	const tokens: string[] = [];
	const lower = text.toLowerCase();
	let match = RECALL_TOKEN_RE.exec(lower);
	while (match !== null) {
		const token = match[0];
		if (token.length >= 3 && !FACT_MATCH_STOPWORDS.has(token) && !isAsciiDigits(token)) tokens.push(token);
		match = RECALL_TOKEN_RE.exec(lower);
	}
	return tokens;
}

export function expandedQueryTokens(tokens: readonly string[]): string[] {
	const expanded: string[] = [];
	const seen = new Set<string>();
	for (const token of tokens) {
		if (!seen.has(token)) {
			seen.add(token);
			expanded.push(token);
		}
		const synonyms = RECALL_SYNONYMS[token];
		if (synonyms === undefined) continue;
		for (const synonym of synonyms) {
			if (seen.has(synonym)) continue;
			seen.add(synonym);
			expanded.push(synonym);
		}
	}
	return expanded;
}

export function minimumRecallRelevance(queryTokens: readonly string[]): number {
	if (queryTokens.length >= 4) return 0.3;
	if (queryTokens.length === 3) return 0.5;
	return 0.15;
}

export function cjkFtsTerms(text: string): string[] {
	const chars: string[] = [];
	for (const ch of text) {
		if (isCjkChar(ch)) chars.push(ch);
	}
	if (chars.length === 0) return [];
	const terms: string[] = [];
	const seen = new Set<string>();
	for (const ch of chars) {
		if (seen.has(ch)) continue;
		seen.add(ch);
		terms.push(ch);
	}
	for (let i = 1; i < chars.length; i++) {
		const previous = chars[i - 1];
		const current = chars[i];
		if (previous === undefined || current === undefined) continue;
		const bigram = `${previous}${current}`;
		if (seen.has(bigram)) continue;
		seen.add(bigram);
		terms.push(`"${bigram}"`);
	}
	return terms;
}

export function ftsQueryTerms(query: string): string[] {
	const terms: string[] = [];
	for (const term of expandedQueryTokens(recallTokens(query))) {
		const escaped = term.replaceAll('"', '""').trim();
		if (escaped) terms.push(`"${escaped}"`);
	}
	return terms;
}

function isAsciiDigits(value: string): boolean {
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		if (code < 48 || code > 57) return false;
	}
	return value.length > 0;
}

/** Count Unicode code points in `value` so supplementary-plane Han characters count as 1. */
export function codePointLength(value: string): number {
	let count = 0;
	for (const _ of value) count++;
	return count;
}

/** Strip leading CJK question/command prefixes when at least 2 code points remain. */
export function stripCjkQuestionAffixes(segment: string): string {
	for (const prefix of CJK_QUESTION_PREFIXES) {
		if (segment.startsWith(prefix)) {
			const rest = segment.slice(prefix.length);
			if (codePointLength(rest) >= 2) return rest;
		}
	}
	return segment;
}

/**
 * Generate code-point-aligned character windows for `segment` across `sizes` (e.g. `[2, 3, 4]`),
 * skipping stop segments and never splitting supplementary-plane surrogate pairs.
 */
export function cjkCodePointShingles(segment: string, sizes: readonly number[] = [2, 3, 4]): string[] {
	const cps = Array.from(segment);
	const out: string[] = [];
	for (const size of sizes) {
		if (size <= 0 || cps.length < size) continue;
		for (let i = 0; i <= cps.length - size; i++) {
			const shingle = cps.slice(i, i + size).join("");
			if (!CJK_STOP_SEGMENTS.has(shingle)) out.push(shingle);
		}
	}
	return out;
}

/**
 * Split a mixed-script token (e.g. `PostgreSQL資料庫` or `TypeScript支援CJK`) into
 * its contiguous non-CJK alphanumeric runs and contiguous CJK runs.
 */
export function splitMixedScriptToken(token: string): { nonCjk: string[]; cjkRuns: string[] } {
	const nonCjk: string[] = [];
	for (const match of token.matchAll(NON_CJK_TOKEN_RUN_RE)) {
		const run = match[0]?.toLowerCase() ?? "";
		if (run.length > 0) nonCjk.push(run);
	}
	const cjkRuns: string[] = [];
	for (const match of token.matchAll(CJK_RUN_RE)) {
		const run = match[0] ?? "";
		if (run.length > 0) cjkRuns.push(run);
	}
	return { nonCjk, cjkRuns };
}

/**
 * Expand a CJK-bearing token into candidate entity/subject segments and 2/3/4-code-point
 * shingles, preserving both intact run shingles (for entities containing particle characters
 * like `東京都`) and particle-split sub-clauses.
 */
export function expandCjkCandidateSegments(token: string, seen: Set<string>): void {
	for (const match of token.matchAll(CJK_RUN_RE)) {
		const run = match[0] ?? "";
		const runLen = codePointLength(run);
		if (runLen < 2) continue;
		if (runLen <= 6 && !CJK_STOP_SEGMENTS.has(run)) seen.add(run);
		const strippedRun = stripCjkQuestionAffixes(run);
		if (strippedRun !== run && codePointLength(strippedRun) <= 6 && !CJK_STOP_SEGMENTS.has(strippedRun)) {
			seen.add(strippedRun);
		}
		for (const shingle of cjkCodePointShingles(run, [2, 3, 4])) seen.add(shingle);

		for (const rawSeg of run.split(CJK_PARTICLE_SPLIT_RE)) {
			for (const seg of [rawSeg, stripCjkQuestionAffixes(rawSeg)]) {
				const segLen = codePointLength(seg);
				if (segLen < 2 || CJK_STOP_SEGMENTS.has(seg)) continue;
				if (segLen <= 6) seen.add(seg);
				if (segLen >= 3) {
					for (const shingle of cjkCodePointShingles(seg, [2, 3, 4])) seen.add(shingle);
				}
			}
		}
	}
}
