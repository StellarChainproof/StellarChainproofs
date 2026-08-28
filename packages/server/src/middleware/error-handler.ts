import { Request, Response, NextFunction } from "express";
import { ErrorSanitizer } from "@chainproof/core";

export function globalErrorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  const cleanErr = ErrorSanitizer.sanitizeError(err);
  console.error("[ChainProof REST Server Error]", cleanErr.message);

  res.status(500).json({
    error: "Internal server error",
    message: cleanErr.message,
  });
}
