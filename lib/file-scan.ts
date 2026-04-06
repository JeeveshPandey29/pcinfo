import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { access, copyFile, mkdir, open, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import type { FilePreviewResponse, FileScanFinding, FileScanResult, SandboxPackageResponse } from "./types";

const execFileAsync = promisify(execFile);

const SCAN_ROOT_NAMES = ["Downloads", "Desktop", "Documents"];
const DOUBLE_EXTENSION_PATTERN = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|zip|rar|mp3|mp4)\.(exe|scr|bat|cmd|ps1|vbs|js|jse|hta|lnk)$/i;
const SUSPICIOUS_EXTENSIONS = new Set([".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jse", ".js", ".hta", ".reg", ".iso", ".img", ".lnk"]);
const PREVIEWABLE_EXTENSIONS = new Map([
  [".txt", "text"],
  [".log", "log"],
  [".json", "json"],
  [".xml", "xml"],
  [".csv", "csv"],
  [".ini", "ini"],
  [".ps1", "powershell"],
  [".bat", "batch"],
  [".cmd", "batch"],
  [".js", "javascript"],
  [".vbs", "vbscript"],
  [".reg", "registry"],
]);
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "AppData", "Program Files", "Program Files (x86)"]);
const SAFE_MICROSOFT_BINARIES = new Set(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "msedge.exe", "explorer.exe", "notepad.exe", "msteams.exe"]);
const MAX_FINDINGS = 60;
const MAX_DEPTH = 4;
const MAX_ENTRIES_PER_DIR = 300;
const PREVIEW_LIMIT_BYTES = 16 * 1024;
const HASH_LIMIT_BYTES = 8 * 1024 * 1024;
const SIGNER_UNKNOWN = "Signature information unavailable";

type Candidate = {
  fullPath: string;
  name: string;
  extension: string;
  category: FileScanFinding["category"];
  reason: string;
  sizeBytes: number;
  modifiedAt: string;
};

type SignatureInfo = {
  signer: string;
  signerStatus: FileScanFinding["signerStatus"];
};

async function exists(target: string) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

function normalizeReason(fileName: string, ext: string) {
  if (DOUBLE_EXTENSION_PATTERN.test(fileName)) {
    return {
      category: "double_extension" as const,
      reason: "File name uses a double extension that can disguise an executable or script as a normal document.",
    };
  }

  return {
    category: "suspicious_type" as const,
    reason: `File uses a script or executable extension (${ext}) in a common user folder and should be reviewed before opening.`,
  };
}

function supportsPreview(extension: string, sizeBytes: number) {
  return PREVIEWABLE_EXTENSIONS.has(extension) && sizeBytes <= 512 * 1024;
}

async function sha256ForFile(fullPath: string, sizeBytes: number) {
  if (sizeBytes > HASH_LIMIT_BYTES) {
    return `Skipped for files larger than ${Math.round(HASH_LIMIT_BYTES / (1024 * 1024))} MB`;
  }

  const content = await readFile(fullPath);
  return createHash("sha256").update(content).digest("hex");
}

async function getAuthenticodeSignature(fullPath: string): Promise<SignatureInfo> {
  try {
    const escaped = fullPath.replace(/'/g, "''");
    const script = [
      `$sig = Get-AuthenticodeSignature -LiteralPath '${escaped}'`,
      "$result = [PSCustomObject]@{",
      "  Status = if ($sig.Status) { $sig.Status.ToString() } else { 'Unknown' }",
      "  Signer = if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject) { $sig.SignerCertificate.Subject } else { '' }",
      "}",
      "$result | ConvertTo-Json -Compress",
    ].join("; ");

    const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-Command", script], {
      timeout: 10000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });

    const parsed = JSON.parse(stdout.trim()) as { Status?: string; Signer?: string };
    const signer = parsed.Signer?.trim();
    const status = (parsed.Status || "Unknown").toLowerCase();

    if (status.includes("valid") && signer) {
      return { signer, signerStatus: "signed" };
    }

    if (status.includes("notsigned") || status.includes("unsigned")) {
      return { signer: "Unsigned file", signerStatus: "unsigned" };
    }

    return { signer: signer || SIGNER_UNKNOWN, signerStatus: signer ? "signed" : "unknown" };
  } catch {
    return { signer: SIGNER_UNKNOWN, signerStatus: "unknown" };
  }
}

function shouldSuppressFinding(candidate: Candidate, signature: SignatureInfo) {
  const lowerName = candidate.name.toLowerCase();
  const signer = signature.signer.toLowerCase();

  if (signature.signerStatus === "signed" && signer.includes("microsoft") && SAFE_MICROSOFT_BINARIES.has(lowerName)) {
    return true;
  }

  if (signature.signerStatus === "signed" && signer.includes("google") && lowerName === "chrome.exe") {
    return true;
  }

  return false;
}

async function scanDirectory(current: string, depth: number, candidates: Candidate[]) {
  if (depth > MAX_DEPTH || candidates.length >= MAX_FINDINGS) {
    return;
  }

  let entries;
  try {
    entries = await readdir(current, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries.slice(0, MAX_ENTRIES_PER_DIR)) {
    if (candidates.length >= MAX_FINDINGS) {
      return;
    }

    const fullPath = path.join(current, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) {
        continue;
      }

      await scanDirectory(fullPath, depth + 1, candidates);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    const lowerName = entry.name.toLowerCase();
    const ext = path.extname(lowerName);
    const isDoubleExtension = DOUBLE_EXTENSION_PATTERN.test(lowerName);
    const isSuspicious = SUSPICIOUS_EXTENSIONS.has(ext);

    if (!isDoubleExtension && !isSuspicious) {
      continue;
    }

    let fileStat;
    try {
      fileStat = await stat(fullPath);
    } catch {
      continue;
    }

    const reason = normalizeReason(entry.name, ext || "no extension");

    candidates.push({
      fullPath,
      name: entry.name,
      extension: ext || "",
      category: reason.category,
      reason: reason.reason,
      sizeBytes: fileStat.size,
      modifiedAt: fileStat.mtime.toISOString(),
    });
  }
}

async function enrichCandidate(candidate: Candidate): Promise<FileScanFinding | null> {
  const [sha256, signature] = await Promise.all([
    sha256ForFile(candidate.fullPath, candidate.sizeBytes).catch(() => "Unable to calculate hash"),
    getAuthenticodeSignature(candidate.fullPath),
  ]);

  if (shouldSuppressFinding(candidate, signature)) {
    return null;
  }

  return {
    id: `${candidate.fullPath}-${candidate.modifiedAt}`,
    name: candidate.name,
    fullPath: candidate.fullPath,
    directory: path.dirname(candidate.fullPath),
    category: candidate.category,
    reason: candidate.reason,
    sizeBytes: candidate.sizeBytes,
    modifiedAt: candidate.modifiedAt,
    extension: candidate.extension,
    sha256,
    signer: signature.signer,
    signerStatus: signature.signerStatus,
    previewSupported: supportsPreview(candidate.extension, candidate.sizeBytes),
  };
}

export async function getFileScan(): Promise<FileScanResult> {
  const userProfile = process.env.USERPROFILE || process.env.HOME || "";
  const roots = SCAN_ROOT_NAMES.map((name) => path.join(userProfile, name));
  const scannedRoots: string[] = [];
  const candidates: Candidate[] = [];

  for (const root of roots) {
    if (!(await exists(root))) {
      continue;
    }

    scannedRoots.push(root);
    await scanDirectory(root, 0, candidates);
  }

  candidates.sort((a, b) => new Date(b.modifiedAt).getTime() - new Date(a.modifiedAt).getTime());

  const findings = (await Promise.all(candidates.slice(0, MAX_FINDINGS).map((candidate) => enrichCandidate(candidate)))).filter(
    (finding): finding is FileScanFinding => Boolean(finding),
  );

  return {
    generatedAt: new Date().toISOString(),
    scannedRoots,
    findings,
  };
}

export async function getFilePreview(targetPath: string): Promise<FilePreviewResponse> {
  const ext = path.extname(targetPath).toLowerCase();
  const languageHint = PREVIEWABLE_EXTENSIONS.get(ext);

  if (!languageHint) {
    throw new Error("This file type is not available for safe preview.");
  }

  const fileHandle = await open(targetPath, "r");
  try {
    const buffer = Buffer.alloc(PREVIEW_LIMIT_BYTES);
    const { bytesRead } = await fileHandle.read(buffer, 0, PREVIEW_LIMIT_BYTES, 0);
    const fileStat = await fileHandle.stat();
    const preview = buffer.subarray(0, bytesRead).toString("utf8").replace(/\u0000/g, "");

    return {
      path: targetPath,
      preview,
      truncated: fileStat.size > PREVIEW_LIMIT_BYTES,
      languageHint,
    };
  } finally {
    await fileHandle.close();
  }
}

function escapeXml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export async function createSandboxPackage(sourcePath: string): Promise<SandboxPackageResponse> {
  const fileName = path.basename(sourcePath);
  const safeStamp = new Date().toISOString().replace(/[:.]/g, "-");
  const packageFolder = path.join(process.cwd(), "sandbox-packages", `safex-${safeStamp}`);
  const copiedFile = path.join(packageFolder, fileName);
  const sandboxFile = path.join(packageFolder, "open-in-sandbox.wsb");
  const sandboxMappedFolder = "C:\\Users\\WDAGUtilityAccount\\Desktop\\SafexSandbox";

  await mkdir(packageFolder, { recursive: true });
  await copyFile(sourcePath, copiedFile);

  const wsb = `<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>${escapeXml(packageFolder)}</HostFolder>
      <SandboxFolder>${escapeXml(sandboxMappedFolder)}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>explorer.exe ${escapeXml(sandboxMappedFolder)}</Command>
  </LogonCommand>
</Configuration>`;

  const readme = [
    "Safex Sandbox Package",
    `Original file: ${sourcePath}`,
    `Copied file: ${copiedFile}`,
    "Open the .wsb file only if Windows Sandbox is installed.",
    "The mapped folder is read-only inside the sandbox to reduce risk.",
  ].join("\r\n");

  await writeFile(sandboxFile, wsb, "utf8");
  await writeFile(path.join(packageFolder, "README.txt"), readme, "utf8");

  return {
    packageFolder,
    sandboxFile,
    copiedFile,
  };
}
