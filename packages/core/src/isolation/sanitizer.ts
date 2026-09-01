export class ErrorSanitizer {
  public static sanitizePath(text: string, sandboxBaseDir?: string): string {
    if (!text) return "";

    let result = text;

    if (sandboxBaseDir) {
      result = result.split(sandboxBaseDir).join("[sandbox]");
    }

    result = result.replace(/(\/tmp\/[a-zA-Z0-9_-]+|\/private\/var\/folders\/[^\s:]+)/g, "[temp_dir]");
    result = result.replace(/(\/Users\/[a-zA-Z0-9_-]+|\/home\/[a-zA-Z0-9_-]+|C:\\Users\\[a-zA-Z0-9_-]+)/g, "[user_home]");
    result = result.replace(/(sk-ant-[a-zA-Z0-9_-]{10,}|cp_live_[a-zA-Z0-9]{10,}|bearer\s+[a-zA-Z0-9._-]{10,})/gi, "[REDACTED_SECRET]");

    return result;
  }

  public static sanitizeError(err: unknown, sandboxBaseDir?: string): Error {
    const rawMessage = err instanceof Error ? err.message : String(err);
    const cleanMessage = ErrorSanitizer.sanitizePath(rawMessage, sandboxBaseDir);

    const cleanErr = new Error(cleanMessage);
    if (err instanceof Error && err.stack) {
      cleanErr.stack = ErrorSanitizer.sanitizePath(err.stack, sandboxBaseDir);
    }
    return cleanErr;
  }
}
