import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type {
  AntivirusProduct,
  DefenderStatus,
  DeviceSnapshot,
  FirewallProfile,
  InstalledApp,
  SecurityCard,
  SecurityStatus,
  StartupEntry,
  TimelineItem,
  UsbDevice,
} from "./types";

const execFileAsync = promisify(execFile);
const POWERSHELL_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const SC_PATH = "C:\\Windows\\System32\\sc.exe";
const REG_PATH = "C:\\Windows\\System32\\reg.exe";
const PNPUTIL_PATH = "C:\\Windows\\System32\\pnputil.exe";
const CMD_PATH = "C:\\Windows\\System32\\cmd.exe";

type OsInfo = {
  Caption?: string;
  Version?: string;
  CSName?: string;
  LastBootUpTime?: string;
};

type DefenderInfo = {
  displayName?: string;
  pathToSignedProductExe?: string;
  productState?: number;
};

type StartupInfo = {
  name?: string;
  command?: string;
  source?: string;
  lastWriteTime?: string;
};

type InstalledInfo = {
  DisplayName?: string;
  DisplayVersion?: string;
  Publisher?: string;
  InstallDate?: string;
};

type LoginSummary = {
  Count?: number;
  LastSeen?: string;
};

type PowerShellSummary = {
  Count?: number;
  LatestTime?: string;
};

type TimelineLog = {
  TimeCreated?: string;
  Id?: number;
  LevelDisplayName?: string;
  ProviderName?: string;
};

async function runCommand(command: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(command, args, {
      cwd: process.cwd(),
      windowsHide: true,
      maxBuffer: 8 * 1024 * 1024,
    });

    return stdout.trim();
  } catch {
    return "";
  }
}

async function runPowerShell(script: string): Promise<string> {
  return runCommand(POWERSHELL_PATH, [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script,
  ]);
}

async function runPowerShellJson<T>(script: string, fallback: T): Promise<T> {
  const output = await runPowerShell(script);

  if (!output) {
    return fallback;
  }

  try {
    return JSON.parse(output) as T;
  } catch {
    return fallback;
  }
}

function toArray<T>(value: T | T[] | null | undefined): T[] {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined || value === "") return [];
  return [value];
}

function formatInstallDate(input?: string): string {
  if (!input || input.length !== 8) return "Unknown";
  return `${input.slice(0, 4)}-${input.slice(4, 6)}-${input.slice(6, 8)}`;
}

function formatDateTime(input?: string): string {
  if (!input) return "Unknown";
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) return input;
  return new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function parseFirewallState(raw: string): FirewallProfile[] {
  if (!raw) return [];

  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const profiles: FirewallProfile[] = [];
  let currentName = "";

  for (const line of lines) {
    if (line.endsWith("Profile Settings:")) {
      currentName = line.replace(" Profile Settings:", "");
      continue;
    }

    if (line.startsWith("State") && currentName) {
      profiles.push({ name: currentName, enabled: /ON/i.test(line) });
    }
  }

  return profiles;
}

function decodeDefenderState(state?: number): string {
  if (typeof state !== "number") return "Unknown";
  const hex = state.toString(16).padStart(6, "0").toUpperCase();
  const enabledNibble = hex.slice(-4, -2);
  return enabledNibble === "10" || enabledNibble === "11" ? "Active" : "Needs review";
}

function boolToStatus(value: boolean): SecurityStatus {
  return value ? "good" : "risk";
}

function makeDetail(what: string, how: string, when: string, confidence: string) {
  return { what, how, when, confidence };
}

function getOverallStatus(cards: SecurityCard[]): SecurityStatus {
  if (cards.some((card) => card.status === "risk")) return "risk";
  if (cards.some((card) => card.status === "watch")) return "watch";
  return "good";
}

function getScore(cards: SecurityCard[]): number {
  let score = 100;
  for (const card of cards) {
    if (card.status === "risk") score -= 18;
    else if (card.status === "watch") score -= 8;
  }
  return Math.max(20, Math.min(100, score));
}

function computeAppTrust(app: { name: string; publisher?: string; installedOn?: string }) {
  const trustedPublishers = ["Microsoft", "Google", "Intel", "HP", "Oracle", "Docker", "NVIDIA", "Realtek"];
  const suspiciousHints = ["unknown", "temp", "helper", "updater", "driver setup"];

  let score = 55;
  const publisher = app.publisher || "Unknown publisher";
  const normalizedName = app.name.toLowerCase();
  const normalizedPublisher = publisher.toLowerCase();

  if (trustedPublishers.some((item) => normalizedPublisher.includes(item.toLowerCase()))) {
    score += 30;
  }

  if (publisher === "Unknown publisher") {
    score -= 18;
  }

  if (suspiciousHints.some((hint) => normalizedName.includes(hint))) {
    score -= 12;
  }

  if (app.installedOn === "Unknown") {
    score -= 5;
  }

  score = Math.max(10, Math.min(98, score));

  if (score >= 80) {
    return {
      trustScore: score,
      trustLevel: "trusted" as const,
      trustReason: publisher === "Unknown publisher" ? "Known software pattern, but publisher data is missing." : `Publisher ${publisher} matches a commonly trusted vendor.`,
    };
  }

  if (score >= 55) {
    return {
      trustScore: score,
      trustLevel: "review" as const,
      trustReason: `This app is not clearly unsafe, but ${publisher === "Unknown publisher" ? "publisher data is missing" : "it is not in the strongest trusted set"}.`,
    };
  }

  return {
    trustScore: score,
    trustLevel: "unknown" as const,
    trustReason: `This app should be reviewed because ${publisher === "Unknown publisher" ? "the publisher is unknown" : "its name or metadata looks less familiar"}.`,
  };
}

function parseDefenderService(raw: string): DefenderStatus {
  const running = /STATE\s+:\s+4\s+RUNNING/i.test(raw);
  const stateMatch = raw.match(/STATE\s+:\s+\d+\s+([^\r\n]+)/i);

  return {
    serviceRunning: running,
    realtimeMonitoring: null,
    serviceState: stateMatch?.[1]?.trim() || "Unknown",
  };
}

function parseDefenderRealtime(raw: string, current: DefenderStatus): DefenderStatus {
  if (!raw) return current;
  const disabledMatch = raw.match(/DpaDisabled\s+REG_DWORD\s+0x([0-9a-f]+)/i);
  if (!disabledMatch) return current;
  const disabled = disabledMatch[1] !== "0";
  return {
    ...current,
    realtimeMonitoring: !disabled,
  };
}

function parseUsbDevices(raw: string): UsbDevice[] {
  if (!raw) return [];

  const blocks = raw.split(/\r?\n\r?\n/);
  const devices: UsbDevice[] = [];
  const ignoredHints = [
    "root hub",
    "host controller",
    "xhc",
    "xhci",
    "usb composite device",
    "generic superspeed usb hub",
    "usb root hub",
    "composite bus enumerator",
    "motherboard resources",
  ];

  for (const block of blocks) {
    const instanceId = block.match(/Instance ID:\s+(.+)/i)?.[1]?.trim() || "";
    const description = block.match(/Device Description:\s+(.+)/i)?.[1]?.trim() || "Unknown USB device";
    const className = block.match(/Class Name:\s+(.+)/i)?.[1]?.trim() || "Unknown";
    const status = block.match(/Status:\s+(.+)/i)?.[1]?.trim() || "Unknown";
    const normalizedDescription = description.toLowerCase();

    if (!instanceId) continue;
    if (!instanceId.startsWith("USB\\") && className.toUpperCase() !== "USB") continue;
    if (ignoredHints.some((hint) => normalizedDescription.includes(hint))) continue;

    devices.push({
      name: description,
      status,
      instanceId,
      className,
    });
  }

  return devices.slice(0, 8);
}

export async function getDeviceSnapshot(): Promise<DeviceSnapshot> {
  const now = new Date().toISOString();

  const os = await runPowerShellJson<OsInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; try { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,CSName,@{N='LastBootUpTime';E={$_.LastBootUpTime.ToString('o')}} | ConvertTo-Json -Compress } catch { '{}' }",
    {},
  );

  const antivirusRaw = await runPowerShellJson<DefenderInfo[] | DefenderInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,pathToSignedProductExe,productState | ConvertTo-Json -Compress } catch { '[]' }",
    [],
  );

  const firewallRaw = await runCommand(CMD_PATH, ["/c", "netsh advfirewall show allprofiles state"]);
  const defenderServiceRaw = await runCommand(SC_PATH, ["query", "WinDefend"]);
  const defenderRealtimeRaw = await runCommand(REG_PATH, ["query", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"]);
  const usbRaw = await runCommand(PNPUTIL_PATH, ["/enum-devices", "/connected"]);

  const startupRaw = await runPowerShellJson<StartupInfo[] | StartupInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $items=@(); foreach($entry in @(@{Path='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';Source='Machine Run'},@{Path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';Source='User Run'})){ if(Test-Path $entry.Path){ $props=Get-ItemProperty $entry.Path; foreach($prop in $props.PSObject.Properties){ if($prop.Name -notlike 'PS*'){ $items += [PSCustomObject]@{name=$prop.Name; command=[string]$prop.Value; source=$entry.Source} } } } }; foreach($folder in @($env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',$env:ProgramData + '\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp')){ if(Test-Path $folder){ Get-ChildItem $folder | ForEach-Object { $items += [PSCustomObject]@{name=$_.Name; source='Startup Folder'; lastWriteTime=$_.LastWriteTime.ToString('o')} } } }; $items | Select-Object -First 12 | ConvertTo-Json -Compress",
    [],
  );

  const appsRaw = await runPowerShellJson<InstalledInfo[] | InstalledInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object { $_.DisplayName } | Sort-Object InstallDate -Descending | Select-Object -First 12 DisplayName,DisplayVersion,Publisher,InstallDate | ConvertTo-Json -Compress",
    [],
  );

  const loginSummary = await runPowerShellJson<LoginSummary>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; try { $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)}; [PSCustomObject]@{ Count = @($events).Count; LastSeen = if(@($events).Count -gt 0){ $events[0].TimeCreated.ToString('o') } else { $null } } | ConvertTo-Json -Compress } catch { '{}' }",
    {},
  );

  const powershellSummary = await runPowerShellJson<PowerShellSummary>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; try { $events = Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 30; [PSCustomObject]@{ Count = @($events).Count; LatestTime = if(@($events).Count -gt 0){ $events[0].TimeCreated.ToString('o') } else { $null } } | ConvertTo-Json -Compress } catch { '{}' }",
    {},
  );

  const timelineRaw = await runPowerShellJson<TimelineLog[] | TimelineLog>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; try { Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 4 | Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},Id,LevelDisplayName,ProviderName | ConvertTo-Json -Compress } catch { '[]' }",
    [],
  );

  const antivirus: AntivirusProduct[] = toArray(antivirusRaw).map((item) => ({
    name: item.displayName || "Windows Security",
    path: item.pathToSignedProductExe || "",
    state: decodeDefenderState(item.productState),
  }));

  const defenderStatus = parseDefenderRealtime(defenderRealtimeRaw, parseDefenderService(defenderServiceRaw));
  const firewallProfiles = parseFirewallState(firewallRaw);
  const usbDevices = parseUsbDevices(usbRaw);

  const startupEntries: StartupEntry[] = toArray(startupRaw).map((item) => ({
    name: item.name || "Unknown startup item",
    command: item.command || "",
    source: item.source || "Unknown source",
    lastWriteTime: item.lastWriteTime || "",
  }));

  const installedApps: InstalledApp[] = toArray(appsRaw).map((item) => {
    const installedOn = formatInstallDate(item.InstallDate);
    const trust = computeAppTrust({
      name: item.DisplayName || "Unknown app",
      publisher: item.Publisher || "Unknown publisher",
      installedOn,
    });

    return {
      name: item.DisplayName || "Unknown app",
      version: item.DisplayVersion || "",
      publisher: item.Publisher || "Unknown publisher",
      installedOn,
      trustScore: trust.trustScore,
      trustLevel: trust.trustLevel,
      trustReason: trust.trustReason,
    };
  });

  const failedLoginCount24h = Number(loginSummary.Count || 0);
  const failedLoginLastSeen = loginSummary.LastSeen ? formatDateTime(loginSummary.LastSeen) : "No recent failed sign-ins";
  const powershellEventCount24h = Number(powershellSummary.Count || 0);
  const powershellLatestTime = powershellSummary.LatestTime ? formatDateTime(powershellSummary.LatestTime) : "No recent PowerShell events";

  const trustedAntivirus = antivirus.some((item) => item.state === "Active") || defenderStatus.serviceRunning;
  const enabledFirewallCount = firewallProfiles.filter((profile) => profile.enabled).length;
  const allFirewallEnabled = firewallProfiles.length > 0 && enabledFirewallCount === firewallProfiles.length;
  const startupWatchCount = startupEntries.filter((item) => /user run|startup folder/i.test(item.source)).length;
  const lowerTrustApps = installedApps.filter((item) => item.trustScore < 60).length;

  const cards: SecurityCard[] = [
    {
      id: "antivirus",
      section: "Protection",
      title: "Windows Defender status",
      value: defenderStatus.serviceRunning ? "Running" : "Not running",
      summary: defenderStatus.realtimeMonitoring === null
        ? `Defender service is ${defenderStatus.serviceState.toLowerCase()}. Real-time protection could not be confirmed from the registry check.`
        : `Defender service is ${defenderStatus.serviceState.toLowerCase()} and real-time protection is ${defenderStatus.realtimeMonitoring ? "on" : "off"}.`,
      status: defenderStatus.serviceRunning && defenderStatus.realtimeMonitoring !== false ? "good" : "watch",
      detail: makeDetail(
        "This checks the WinDefend service and a Defender real-time protection registry value.",
        `Service state: ${defenderStatus.serviceState}. Real-time monitoring: ${defenderStatus.realtimeMonitoring === null ? "unknown" : defenderStatus.realtimeMonitoring ? "enabled" : "disabled"}.`,
        `Collected ${formatDateTime(now)}.`,
        "High confidence for service state, medium confidence for real-time protection because registry policies can vary by device.",
      ),
    },
    {
      id: "firewall",
      section: "Protection",
      title: "Firewall profiles",
      value: allFirewallEnabled ? "All on" : `${enabledFirewallCount}/${firewallProfiles.length || 3} on`,
      summary: allFirewallEnabled ? "Domain, private, and public firewall profiles are enabled." : "One or more firewall profiles are disabled or could not be confirmed.",
      status: boolToStatus(allFirewallEnabled),
      detail: makeDetail(
        "This checks built-in Windows firewall profile states.",
        firewallProfiles.length > 0 ? firewallProfiles.map((profile) => `${profile.name}: ${profile.enabled ? "On" : "Off"}`).join(". ") : "The firewall command did not return individual profile states.",
        `Collected ${formatDateTime(now)}.`,
        firewallProfiles.length > 0 ? "High confidence because the profile state comes from Windows firewall output." : "Low confidence because firewall profile details were unavailable.",
      ),
    },
    {
      id: "usb-devices",
      section: "Protection",
      title: "Connected USB devices",
      value: usbDevices.length === 0 ? "None" : String(usbDevices.length),
      summary: usbDevices.length > 0 ? `${usbDevices.length} external USB devices are currently visible to Windows.` : "No external USB device detected.",
      status: (usbDevices.length > 3 ? "watch" : "good") as SecurityStatus,
      detail: makeDetail(
        "This lists currently connected USB devices from Windows Plug and Play enumeration.",
        usbDevices.length > 0 ? usbDevices.map((device) => `${device.name} (${device.status})`).join(". ") : "Windows did not expose connected USB devices in the current snapshot.",
        `Collected ${formatDateTime(now)}.`,
        "Medium confidence because this shows currently enumerated USB hardware, not every historical insertion event.",
      ),
    },
    {
      id: "failed-logins",
      section: "Behavior",
      title: "Failed sign-in attempts",
      value: String(failedLoginCount24h),
      summary: failedLoginCount24h > 0 ? `${failedLoginCount24h} failed Windows sign-in attempts were logged in the last 24 hours.` : "No failed Windows sign-in attempts were found in the last 24 hours.",
      status: (failedLoginCount24h >= 5 ? "risk" : failedLoginCount24h > 0 ? "watch" : "good") as SecurityStatus,
      detail: makeDetail(
        "This counts Windows Security event ID 4625, which means a failed logon attempt.",
        failedLoginCount24h > 0 ? `The Security log recorded ${failedLoginCount24h} failed sign-in events in the last 24 hours.` : "The Security log did not show failed sign-ins during the last 24 hours.",
        failedLoginCount24h > 0 ? `Most recent failure was seen at ${failedLoginLastSeen}.` : "Checked the last 24 hours.",
        "High confidence when access to the local Security log is available.",
      ),
    },
    {
      id: "powershell",
      section: "Behavior",
      title: "PowerShell activity",
      value: String(powershellEventCount24h),
      summary: powershellEventCount24h > 0 ? `${powershellEventCount24h} Windows PowerShell events were found in the last 24 hours.` : "No Windows PowerShell events were found in the last 24 hours.",
      status: powershellEventCount24h >= 8 ? "watch" : "good",
      detail: makeDetail(
        "This counts events in the Windows PowerShell log to show scripting activity volume.",
        powershellEventCount24h > 0 ? `Windows recorded ${powershellEventCount24h} recent PowerShell engine events.` : "The Windows PowerShell log did not return recent engine events during the last 24 hours.",
        powershellEventCount24h > 0 ? `Most recent PowerShell event was seen at ${powershellLatestTime}.` : "Checked the last 24 hours.",
        "Medium confidence because event volume alone does not prove something is malicious.",
      ),
    },
    {
      id: "startup-items",
      section: "Trust",
      title: "Startup entries",
      value: String(startupEntries.length),
      summary: startupEntries.length > 0 ? `${startupEntries.length} startup entries were found from Run keys and startup folders.` : "No startup entries were found from the startup locations checked.",
      status: startupWatchCount >= 4 ? "watch" : "good",
      detail: makeDetail(
        "This lists applications configured to launch automatically when Windows starts.",
        startupEntries.length > 0 ? startupEntries.map((item) => `${item.name} from ${item.source}`).join(". ") : "No startup entries were returned from registry Run keys or startup folders.",
        startupEntries.find((entry) => entry.lastWriteTime) ? `Latest startup timestamp seen at ${formatDateTime(startupEntries.find((entry) => entry.lastWriteTime)?.lastWriteTime)}.` : "Collected from current startup locations.",
        "Medium confidence because some apps start from scheduled tasks or services instead.",
      ),
    },
    {
      id: "recent-apps",
      section: "Trust",
      title: "Installed software trust",
      value: lowerTrustApps > 0 ? `${lowerTrustApps} review` : "Looks stable",
      summary: installedApps.length > 0 ? `The software list was scored by vendor familiarity, naming pattern, and install metadata quality.` : "No installed software list was returned from the uninstall registry keys.",
      status: lowerTrustApps >= 2 ? "watch" : "good",
      detail: makeDetail(
        "This applies a local trust score to installed software using publisher and metadata heuristics.",
        installedApps.length > 0 ? installedApps.map((item) => `${item.name}: ${item.trustScore}`).join(". ") : "Windows did not return recent installed software metadata for this snapshot.",
        `Collected ${formatDateTime(now)}.`,
        "Medium confidence because this is a heuristic score, not malware verdicting.",
      ),
    },
  ];

  const eventTimeline: TimelineItem[] = toArray(timelineRaw).slice(0, 3).map((item, index) => ({
    id: `event-${index}`,
    title: item.ProviderName ? `${item.ProviderName} event ${item.Id || ""}`.trim() : `Windows event ${index + 1}`,
    summary: item.Id === 403 ? "PowerShell engine state changed on this device." : item.LevelDisplayName ? `${item.LevelDisplayName} event recorded by Windows.` : "Windows recorded a local event.",
    time: formatDateTime(item.TimeCreated),
    status: (item.Id === 403 ? "watch" : "good") as SecurityStatus,
    detail: makeDetail(
      "This timeline item comes from recent Windows event log activity on your laptop.",
      item.ProviderName ? `${item.ProviderName} wrote event ID ${item.Id || "unknown"} to the local event log.` : "A local Windows provider wrote this event, but the provider name was unavailable.",
      item.TimeCreated ? `Event time: ${formatDateTime(item.TimeCreated)}.` : "No event time was returned.",
      "High confidence that the event exists locally; medium confidence for risk interpretation.",
    ),
  }));

  const timeline: TimelineItem[] = [
    {
      id: "timeline-defender",
      title: defenderStatus.serviceRunning ? "Windows Defender service is running" : "Windows Defender service needs review",
      summary: defenderStatus.realtimeMonitoring === false ? "Real-time protection appears disabled." : "Defender service state was checked locally.",
      time: formatDateTime(now),
      status: (defenderStatus.serviceRunning ? "good" : "watch") as SecurityStatus,
      detail: cards[0].detail,
    },
    {
      id: "timeline-usb",
      title: usbDevices.length > 0 ? "USB devices are connected right now" : "No USB devices detected in current snapshot",
      summary: usbDevices.length > 0 ? usbDevices.map((device) => device.name).slice(0, 2).join(", ") : "No external USB device detected in this snapshot.",
      time: formatDateTime(now),
      status: (usbDevices.length > 3 ? "watch" : "good") as SecurityStatus,
      detail: cards[2].detail,
    },
    {
      id: "timeline-logins",
      title: failedLoginCount24h > 0 ? "Recent failed sign-in activity detected" : "No failed sign-ins in last 24 hours",
      summary: failedLoginCount24h > 0 ? `${failedLoginCount24h} sign-in failures were seen in the Security log.` : "The local Security log did not show failed sign-ins in the last day.",
      time: failedLoginCount24h > 0 ? failedLoginLastSeen : formatDateTime(now),
      status: (failedLoginCount24h >= 5 ? "risk" : failedLoginCount24h > 0 ? "watch" : "good") as SecurityStatus,
      detail: cards[3].detail,
    },
    ...eventTimeline,
  ].slice(0, 6);

  const overallStatus = getOverallStatus(cards);
  const score = getScore(cards);
  const overviewHeadline = overallStatus === "risk"
    ? "Your laptop needs attention in a few security areas."
    : overallStatus === "watch"
      ? "Your laptop looks mostly healthy, with a few things worth checking."
      : "Your laptop looks healthy based on the local signals that were checked.";

  const overviewExplanation = [
    defenderStatus.serviceRunning ? "Windows Defender service is running." : "Windows Defender service needs review.",
    allFirewallEnabled ? "Firewall profiles appear enabled." : "At least one firewall profile needs review.",
    usbDevices.length > 0 ? `${usbDevices.length} USB devices are currently visible to Windows.` : "No active USB devices were found in the current snapshot.",
    lowerTrustApps > 0 ? `${lowerTrustApps} installed apps should be reviewed with the trust score.` : "Installed software trust scoring looks stable.",
  ].join(" ");

  return {
    generatedAt: now,
    deviceName: os.CSName || process.env.COMPUTERNAME || "This PC",
    osName: os.Caption || "Windows",
    osVersion: os.Version || "Unknown",
    lastBootTime: formatDateTime(os.LastBootUpTime),
    antivirus,
    defenderStatus,
    firewallProfiles,
    usbDevices,
    startupEntries,
    installedApps,
    failedLoginCount24h,
    powershellEventCount24h,
    timeline,
    cards,
    overviewStory: {
      headline: overviewHeadline,
      explanation: overviewExplanation,
      status: overallStatus,
      score,
    },
  };
}




