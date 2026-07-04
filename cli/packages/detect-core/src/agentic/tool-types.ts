// Tool-only type contract. Kept separate from schema.ts so tools.ts can be
// imported without pulling zod into hot paths.

export interface ListFilesEntry {
  name: string;
  type: 'file' | 'dir';
}

export interface ReadFileResult {
  /** Path relative to the sandbox repo root, forward-slash separated as fs
   *  returns. */
  path: string;
  lineStart: number;
  lineEnd: number;
  content: string;
  /** True when the byte cap clipped the returned content. */
  truncated: boolean;
  /** When a line-range read was clipped by the byte cap, the last line that
   *  fit. Absent if no clipping occurred or no range was requested. */
  clippedAtLine?: number;
  /** True when lineStart exceeded the file's actual line count. Content will
   *  be empty in that case. */
  outOfRange?: boolean;
  /** Total line count in the underlying file. Useful for callers to detect
   *  when a requested range was capped to the file's tail. */
  totalLines?: number;
}

export interface GrepHit {
  file: string;
  line: number;
  /** Matched line, without trailing newline. */
  match: string;
}

export interface DefinitionHit {
  file: string;
  line: number;
  preview: string;
}

export interface ReferenceHit {
  file: string;
  line: number;
  context: string;
}

export interface AgentTools {
  list_files(p: string): Promise<ListFilesEntry[]>;
  read_file(
    p: string,
    lineStart?: number,
    lineEnd?: number,
  ): Promise<ReadFileResult>;
  grep(
    pattern: string,
    options?: {
      paths?: string[];
      ignoreCase?: boolean;
      maxResults?: number;
    },
  ): Promise<GrepHit[]>;
  find_definition(symbol: string, hintFile?: string): Promise<DefinitionHit[]>;
  find_references(symbol: string, hintFile?: string): Promise<ReferenceHit[]>;
}

export interface CreateToolsOptions {
  /** Per-call byte cap for read_file. Defaults to 64KB, capped at 256KB. */
  readFileMaxBytes?: number;
  /** Per-call timeout for ripgrep invocations. Default 5000ms. */
  ripgrepTimeoutMs?: number;
  /** Default maxResults for grep. */
  grepDefaultMaxResults?: number;
}
