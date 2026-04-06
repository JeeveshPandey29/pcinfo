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
};

export type AntivirusProduct = {
  name: string;
  state: string;
  path?: string;
};

export type FirewallProfile = {
  name: string;
  enabled: boolean;
};

export type DeviceSnapshot = {
  generatedAt: string;
  deviceName: string;
  osName: string;
  osVersion: string;
  lastBootTime: string;
  antivirus: AntivirusProduct[];
  firewallProfiles: FirewallProfile[];
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

