import { ENV, PIIDetection } from '../types';

/**
 * Redact sensitive information from text before sending to client
 * This prevents sensitive data from being exposed in responses
 */
export function redactSensitiveData(text: string): string {
	return text
		.replace(/AKIA[0-9A-Z]{16}/g, "[REDACTED_AWS_KEY]")
		.replace(/-----BEGIN [\w\s]+ KEY-----[\s\S]+?-----END [\w\s]+ KEY-----/g, "[REDACTED_PRIVATE_KEY]")
		.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]");
}

/**
 * Detect PII in text using pattern matching and AI (similar to v1/analyze-context)
 * Returns array of detections with type, value, and confidence
 */
export async function detectPII(
	text: string,
	env: ENV,
	options?: {
		customPatterns?: Array<{ name: string; pattern: string; pattern_type: string }>;
		useAI?: boolean;
	},
): Promise<PIIDetection[]> {
	const detections: PIIDetection[] = [];

	// Pattern-based detection (fast, runs first)
	const patterns = {
		EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
		PHONE_NUMBER: /\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b/g,
		SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
		CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
		IP_ADDRESS: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
		API_KEY: /\b(?:api[_-]?key|apikey|token)[:\s=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?/gi,
		PASSWORD: /\b(?:password|passwd|pwd)[:\s=]+['\"]?([^\s'"]{6,})['\"]?/gi,
		AWS_KEY: /\b(AKIA[0-9A-Z]{16})\b/g,
		SLACK_TOKEN: /\b(xox[pborsa]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,32})\b/g,
		JWT: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/g,
	};

	// Add built-in patterns
	for (const [type, pattern] of Object.entries(patterns)) {
		const matches = text.matchAll(pattern);
		for (const match of matches) {
			detections.push({
				type,
				value: match[0],
				confidence: 95,
				reason: "Pattern match",
			});
		}
	}

	// Add custom patterns from user
	if (options?.customPatterns && options.customPatterns.length > 0) {
		for (const customPattern of options.customPatterns) {
			try {
				const regex = new RegExp(customPattern.pattern, "gi");
				const matches = text.matchAll(regex);
				for (const match of matches) {
					detections.push({
						type: customPattern.pattern_type || customPattern.name,
						value: match[0],
						confidence: 90,
						reason: "Custom pattern",
					});
				}
			} catch (error) {
				console.error(`Invalid custom pattern ${customPattern.name}:`, error);
				// Continue with other patterns
			}
		}
	}

	// If text is short enough and we have AI available, use AI for contextual detection
	const useAI = options?.useAI !== undefined ? options.useAI : true;
	if (text.length <= 2000 && env.AI && useAI) {
		try {
			const aiResponse = await env.AI.run("@cf/meta/llama-3-8b-instruct", {
				messages: [
					{
						role: "system",
						content: `You are a privacy-focused PII detector. Analyze text for personally identifiable information.
Return ONLY a valid JSON array of detected PII items. Each item should have:
{
  "type": string (e.g., "NAME", "ADDRESS", "PHONE_NUMBER"),
  "value": string (the actual detected text),
  "confidence": number (0-100)
}
If no PII is detected, return an empty array: []
Be conservative - flag anything that might be sensitive.`,
					},
					{
						role: "user",
						content: `Analyze this text for PII:\n\n"${text}"`,
					},
				],
				temperature: 0.1,
				max_tokens: 300,
			});

			const responseText = aiResponse.response || JSON.stringify(aiResponse);
			const jsonMatch = responseText.match(/\[[\s\S]*\]/);
			if (jsonMatch) {
				const aiDetections = JSON.parse(jsonMatch[0]);
				// Merge AI detections with pattern detections (avoid duplicates)
				for (const aiDet of aiDetections) {
					const isDuplicate = detections.some(
						(d) => d.type === aiDet.type && d.value.toLowerCase() === aiDet.value.toLowerCase(),
					);
					if (!isDuplicate) {
						detections.push({
							type: aiDet.type,
							value: aiDet.value,
							confidence: aiDet.confidence || 80,
							reason: "AI detection",
						});
					}
				}
			}
		} catch (aiError) {
			console.error("AI detection error:", aiError);
			// Continue with pattern-based detections only
		}
	}

	return detections;
}

/**
 * Redact PII from text by replacing detected values with [REDACTED] placeholders
 */
export async function redactPII(
	text: string,
	env: ENV,
	options?: {
		customPatterns?: Array<{ name: string; pattern: string; pattern_type: string }>;
		useAI?: boolean;
	},
): Promise<string> {
	const detections = await detectPII(text, env, options);
	let redactedText = text;

	// Sort detections by value length (longest first) to avoid partial replacements
	detections.sort((a, b) => b.value.length - a.value.length);

	for (const detection of detections) {
		const placeholder = `[REDACTED ${detection.type}]`;
		// Use a more robust replacement to handle special regex characters
		const escapedValue = detection.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		redactedText = redactedText.replace(new RegExp(escapedValue, "gi"), placeholder);
	}

	return redactedText;
}

