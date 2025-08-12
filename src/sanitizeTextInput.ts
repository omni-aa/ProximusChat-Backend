export default function sanitizeText(input: string, maxLen: number = 50): string {
    let clean = input.trim();
    clean = clean.replace(/[^a-zA-Z0-9 _-]/g, "");
    if (clean.length > maxLen) clean = clean.substring(0, maxLen);
    return clean;
}