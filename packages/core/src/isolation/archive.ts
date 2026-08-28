import * as zlib from "zlib";
import { ArchiveExtractResult, IsolationLimits } from "./types";
import { DEFAULT_ISOLATION_LIMITS } from "./sandbox";

export class SafeArchiveExtractor {
  private limits: IsolationLimits;

  constructor(customLimits?: Partial<IsolationLimits>) {
    this.limits = {
      ...DEFAULT_ISOLATION_LIMITS,
      ...customLimits,
    };
  }

  public extractZipBuffer(buffer: Buffer): ArchiveExtractResult {
    let uncompressedTotalSize = 0;
    const files: Array<{ path: string; content: string }> = [];

    let offset = 0;
    const bufferLength = buffer.length;

    while (offset < bufferLength - 4) {
      const signature = buffer.readUInt32LE(offset);

      if (signature === 0x04034b50) {
        if (files.length >= this.limits.maxFileCount) {
          throw new Error(`Zip bomb defense: file count exceeds max limit (${this.limits.maxFileCount})`);
        }

        const compressionMethod = buffer.readUInt16LE(offset + 8);
        const compressedSize = buffer.readUInt32LE(offset + 18);
        const uncompressedSize = buffer.readUInt32LE(offset + 22);
        const fileNameLength = buffer.readUInt16LE(offset + 26);
        const extraFieldLength = buffer.readUInt16LE(offset + 28);

        const fileName = buffer.toString("utf-8", offset + 30, offset + 30 + fileNameLength);
        const dataStart = offset + 30 + fileNameLength + extraFieldLength;

        if (fileName.includes("..") || fileName.startsWith("/") || fileName.startsWith("\\")) {
          throw new Error(`Illegal path traversal attempt in zip archive entry: '${fileName}'`);
        }

        if (compressedSize > 0 && uncompressedSize > 0) {
          const ratio = uncompressedSize / compressedSize;
          if (ratio > this.limits.maxCompressionRatio) {
            throw new Error(
              `Zip bomb defense: compression ratio (${ratio.toFixed(1)}:1) exceeds max allowed limit (${this.limits.maxCompressionRatio}:1)`
            );
          }
        }

        if (uncompressedSize > this.limits.maxSingleFileSizeBytes) {
          throw new Error(
            `Zip entry '${fileName}' uncompressed size (${uncompressedSize} bytes) exceeds single file limit (${this.limits.maxSingleFileSizeBytes} bytes)`
          );
        }

        uncompressedTotalSize += uncompressedSize;
        if (uncompressedTotalSize > this.limits.maxTotalSizeBytes) {
          throw new Error(
            `Zip bomb defense: total extracted size (${uncompressedTotalSize} bytes) exceeds limit (${this.limits.maxTotalSizeBytes} bytes)`
          );
        }

        if (!fileName.endsWith("/") && !fileName.endsWith("\\")) {
          const compressedData = buffer.subarray(dataStart, dataStart + compressedSize);
          let uncompressedData: Buffer;

          if (compressionMethod === 0) {
            uncompressedData = compressedData;
          } else if (compressionMethod === 8) {
            try {
              uncompressedData = zlib.inflateRawSync(compressedData);
            } catch (inflateErr) {
              throw new Error(`Failed to decompress zip entry '${fileName}': ${inflateErr}`);
            }
          } else {
            offset += 30 + fileNameLength + extraFieldLength + compressedSize;
            continue;
          }

          files.push({
            path: fileName,
            content: uncompressedData.toString("utf-8"),
          });
        }

        offset = dataStart + compressedSize;
      } else {
        offset++;
      }
    }

    return {
      files,
      totalSizeBytes: uncompressedTotalSize,
      fileCount: files.length,
    };
  }
}
