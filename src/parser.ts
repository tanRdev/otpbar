const OTP_PATTERNS: RegExp[] = [
  // "code: 123456" or "verification code: 1234"
  /(?:code|verification|otp|pin)[:\s]+(\d{4,8})/i,
  // "123456 is your code"
  /(\d{4,8})\s+is\s+your\s+(?:code|otp|verification|pin)/i,
  // "Your code is 123456"
  /your\s+(?:code|otp|verification|pin)\s+is[:\s]+(\d{4,8})/i,
  // "Enter 123456 to verify"
  /enter[:\s]+(\d{4,8})\s+to\s+(?:verify|confirm)/i,
  // Standalone 6-digit (fallback, lower priority)
  /\b(\d{6})\b/
];

export function extractOTP(text: string | null | undefined): string | null {
  if (!text) return null;

  for (const pattern of OTP_PATTERNS) {
    const match = text.match(pattern);
    if (match?.[1]) {
      return match[1];
    }
  }
  return null;
}
