export type SecurityStatus = "good" | "watch" | "risk";

export type SecurityCard = {
  id: string;
  section: string;
  title: string;
  value: string;
  summary: string;
  status: SecurityStatus;
  detail: {
    what: string;
    how: string;
    when: string;
    confidence: string;
  };
};

export type TimelineItem = {
  id: string;
  title: string;
  summary: string;
  time: string;
  status: SecurityStatus;
  detail: {
    what: string;
    how: string;
    when: string;
    confidence: string;
  };
};

export type StartupEntry = {
  name: string;
  command?: string;
  source: string;
  lastWriteTime?: string;
};

export type InstalledApp = {
  name: string;
  version?: string;
  publisher?: string;
  installedOn?: string;
  trustScore: number;
  trustLevel: "trusted" | "review" | "unknown";
  trustReason: string;
};

export type AntivirusProduct = {
  name: string;
  state: string;
  path?: string;
};

export type DefenderStatus = {
  serviceRunning: boolean;
  realtimeMonitoring: boolean | null;
  serviceState: string;
};

export type FirewallProfile = {
  name: string;
  enabled: boolean;
};

export type UsbDevice = {
  name: string;
  status: string;
  instanceId: string;
  className: string;
};

export type FileSignerStatus = "signed" | "unsigned" | "unknown";

export type FileScanFinding = {
  id: string;
  name: string;
  fullPath: string;
  directory: string;
  category: "double_extension" | "suspicious_type";
  reason: string;
  sizeBytes: number;
  modifiedAt: string;
  extension: string;
  sha256: string;
  signer: string;
  signerStatus: FileSignerStatus;
  previewSupported: boolean;
};

export type FileScanResult = {
  generatedAt: string;
  scannedRoots: string[];
  findings: FileScanFinding[];
};

export type FilePreviewResponse = {
  path: string;
  preview: string;
  truncated: boolean;
  languageHint: string;
};

export type SandboxPackageResponse = {
  packageFolder: string;
  sandboxFile: string;
  copiedFile: string;
};

export type DeviceSnapshot = {
  generatedAt: string;
  deviceName: string;
  osName: string;
  osVersion: string;
  lastBootTime: string;
  antivirus: AntivirusProduct[];
  defenderStatus: DefenderStatus;
  firewallProfiles: FirewallProfile[];
  usbDevices: UsbDevice[];
  startupEntries: StartupEntry[];
  installedApps: InstalledApp[];
  failedLoginCount24h: number;
  powershellEventCount24h: number;
  timeline: TimelineItem[];
  cards: SecurityCard[];
  overviewStory: {
    headline: string;
    explanation: string;
    status: SecurityStatus;
    score: number;
  };
};

export type AskResponse = {
  answer: string;
  source: "openai" | "local";
};
