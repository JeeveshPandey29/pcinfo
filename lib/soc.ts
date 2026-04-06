import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type {
  AntivirusProduct,
  DeviceSnapshot,
  FirewallProfile,
  InstalledApp,
  SecurityCard,
  SecurityStatus,
  StartupEntry,
  TimelineItem,
} from "./types";

const execFileAsync = promisify(execFile);
const POWERSHELL_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

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

async function runPowerShell(script: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync(
      POWERSHELL_PATH,
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
      {
        cwd: process.cwd(),
        windowsHide: true,
        maxBuffer: 8 * 1024 * 1024,
      },
    );

    return stdout.trim();
  } catch {
    return "";
  }
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
  if (Array.isArray(value)) {
    return value;
  }

  if (value === null || value === undefined || value === "") {
    return [];
  }

  return [value];
}

function formatInstallDate(input?: string): string {
  if (!input || input.length !== 8) {
    return "Unknown";
  }

  return `${input.slice(0, 4)}-${input.slice(4, 6)}-${input.slice(6, 8)}`;
}

function formatDateTime(input?: string): string {
  if (!input) {
    return "Unknown";
  }

  const date = new Date(input);
  if (Number.isNaN(date.getTime())) {
    return input;
  }

  return new Intl.DateTimeFormat("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function parseFirewallState(raw: string): FirewallProfile[] {
  if (!raw) {
    return [];
  }

  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const profiles: FirewallProfile[] = [];
  let currentName = "";

  for (const line of lines) {
    if (line.endsWith("Profile Settings:")) {
      currentName = line.replace(" Profile Settings:", "");
      continue;
    }

    if (line.startsWith("State") && currentName) {
      profiles.push({
        name: currentName,
        enabled: /ON/i.test(line),
      });
    }
  }

  return profiles;
}

function decodeDefenderState(state?: number): string {
  if (typeof state !== "number") {
    return "Unknown";
  }

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
  if (cards.some((card) => card.status === "risk")) {
    return "risk";
  }

  if (cards.some((card) => card.status === "watch")) {
    return "watch";
  }

  return "good";
}

function getScore(cards: SecurityCard[]): number {
  let score = 100;

  for (const card of cards) {
    if (card.status === "risk") {
      score -= 18;
    } else if (card.status === "watch") {
      score -= 8;
    }
  }

  return Math.max(20, Math.min(100, score));
}

export async function getDeviceSnapshot(): Promise<DeviceSnapshot> {
  const os = await runPowerShellJson<OsInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,CSName,@{N='LastBootUpTime';E={$_.LastBootUpTime.ToString('o')}} | ConvertTo-Json -Compress",
    {},
  );

  const antivirusRaw = await runPowerShellJson<DefenderInfo[] | DefenderInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,pathToSignedProductExe,productState | ConvertTo-Json -Compress",
    [],
  );

  const firewallRaw = await runPowerShell("netsh advfirewall show allprofiles state");

  const startupRaw = await runPowerShellJson<StartupInfo[] | StartupInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $items=@(); foreach($entry in @(@{Path='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';Source='Machine Run'},@{Path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';Source='User Run'})){ if(Test-Path $entry.Path){ $props=Get-ItemProperty $entry.Path; foreach($prop in $props.PSObject.Properties){ if($prop.Name -notlike 'PS*'){ $items += [PSCustomObject]@{name=$prop.Name; command=[string]$prop.Value; source=$entry.Source} } } } }; foreach($folder in @($env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',$env:ProgramData + '\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp')){ if(Test-Path $folder){ Get-ChildItem $folder | ForEach-Object { $items += [PSCustomObject]@{name=$_.Name; source='Startup Folder'; lastWriteTime=$_.LastWriteTime.ToString('o')} } } }; $items | Select-Object -First 12 | ConvertTo-Json -Compress",
    [],
  );

  const appsRaw = await runPowerShellJson<InstalledInfo[] | InstalledInfo>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object { $_.DisplayName } | Sort-Object InstallDate -Descending | Select-Object -First 10 DisplayName,DisplayVersion,Publisher,InstallDate | ConvertTo-Json -Compress",
    [],
  );

  const loginSummary = await runPowerShellJson<LoginSummary>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)}; [PSCustomObject]@{ Count = @($events).Count; LastSeen = if(@($events).Count -gt 0){ $events[0].TimeCreated.ToString('o') } else { $null } } | ConvertTo-Json -Compress",
    {},
  );

  const powershellSummary = await runPowerShellJson<PowerShellSummary>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $events = Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 30; [PSCustomObject]@{ Count = @($events).Count; LatestTime = if(@($events).Count -gt 0){ $events[0].TimeCreated.ToString('o') } else { $null } } | ConvertTo-Json -Compress",
    {},
  );

  const timelineRaw = await runPowerShellJson<TimelineLog[] | TimelineLog>(
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 4 | Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},Id,LevelDisplayName,ProviderName | ConvertTo-Json -Compress",
    [],
  );

  const antivirus: AntivirusProduct[] = toArray(antivirusRaw).map((item) => ({
    name: item.displayName || "Windows Security",
    path: item.pathToSignedProductExe || "",
    state: decodeDefenderState(item.productState),
  }));

  const firewallProfiles = parseFirewallState(firewallRaw);

  const startupEntries: StartupEntry[] = toArray(startupRaw).map((item) => ({
    name: item.name || "Unknown startup item",
    command: item.command || "",
    source: item.source || "Unknown source",
    lastWriteTime: item.lastWriteTime || "",
  }));

  const installedApps: InstalledApp[] = toArray(appsRaw).map((item) => ({
    name: item.DisplayName || "Unknown app",
    version: item.DisplayVersion || "",
    publisher: item.Publisher || "Unknown publisher",
    installedOn: formatInstallDate(item.InstallDate),
  }));

  const failedLoginCount24h = Number(loginSummary.Count || 0);
  const failedLoginLastSeen = loginSummary.LastSeen
    ? formatDateTime(loginSummary.LastSeen)
    : "No recent failed sign-ins";

  const powershellEventCount24h = Number(powershellSummary.Count || 0);
  const powershellLatestTime = powershellSummary.LatestTime
    ? formatDateTime(powershellSummary.LatestTime)
    : "No recent PowerShell events";

  const trustedAntivirus = antivirus.some((item) => item.state === "Active");
  const enabledFirewallCount = firewallProfiles.filter((profile) => profile.enabled).length;
  const allFirewallEnabled = firewallProfiles.length > 0 && enabledFirewallCount === firewallProfiles.length;
  const startupWatchCount = startupEntries.filter((item) => /user run|startup folder/i.test(item.source)).length;

  const todayInstall = new Date().toISOString().slice(0, 10);
  const hasFreshInstall = installedApps.some((item) => item.installedOn === todayInstall);

  const cards: SecurityCard[] = [
    {
      id: "antivirus",
      section: "Protection",
      title: "Antivirus protection",
      value: trustedAntivirus ? "Active" : "Needs review",
      summary: trustedAntivirus
        ? `${antivirus[0]?.name || "Windows Security"} is reporting an active state.`
        : "No active antivirus provider could be confirmed from Windows Security Center in this session.",
      status: trustedAntivirus ? "good" : "watch",
      detail: makeDetail(
        "This checks the antivirus provider registered with Windows Security Center.",
        antivirus.length > 0
          ? `Windows reported ${antivirus.map((item) => item.name).join(", ")} as installed protection software.`
          : "Windows did not return a registered antivirus provider entry during this snapshot.",
        `Collected ${formatDateTime(new Date().toISOString())}.`,
        trustedAntivirus
          ? "High confidence because the provider is registered directly with Windows Security Center."
          : "Medium confidence because some environments hide or restrict this provider data.",
      ),
    },
    {
      id: "firewall",
      section: "Protection",
      title: "Firewall profiles",
      value: allFirewallEnabled ? "All on" : `${enabledFirewallCount}/${firewallProfiles.length || 3} on`,
      summary: allFirewallEnabled
        ? "Domain, private, and public firewall profiles are enabled."
        : "One or more firewall profiles are disabled or could not be confirmed.",
      status: boolToStatus(allFirewallEnabled),
      detail: makeDetail(
        "This checks built-in Windows firewall profile states.",
        firewallProfiles.length > 0
          ? firewallProfiles.map((profile) => `${profile.name}: ${profile.enabled ? "On" : "Off"}`).join(". ")
          : "The firewall command did not return individual profile states.",
        `Collected ${formatDateTime(new Date().toISOString())}.`,
        firewallProfiles.length > 0
          ? "High confidence because the profile state comes from Windows firewall output."
          : "Low confidence because firewall profile details were unavailable.",
      ),
    },
    {
      id: "failed-logins",
      section: "Behavior",
      title: "Failed sign-in attempts",
      value: String(failedLoginCount24h),
      summary:
        failedLoginCount24h > 0
          ? `${failedLoginCount24h} failed Windows sign-in attempts were logged in the last 24 hours.`
          : "No failed Windows sign-in attempts were found in the last 24 hours.",
      status: (failedLoginCount24h >= 5 ? "risk" : failedLoginCount24h > 0 ? "watch" : "good") as SecurityStatus,
      detail: makeDetail(
        "This counts Windows Security event ID 4625, which means a failed logon attempt.",
        failedLoginCount24h > 0
          ? `The Security log recorded ${failedLoginCount24h} failed sign-in events in the last 24 hours.`
          : "The Security log did not show failed sign-ins during the last 24 hours.",
        failedLoginCount24h > 0 ? `Most recent failure was seen at ${failedLoginLastSeen}.` : "Checked the last 24 hours.",
        "High confidence when access to the local Security log is available.",
      ),
    },
    {
      id: "powershell",
      section: "Behavior",
      title: "PowerShell activity",
      value: String(powershellEventCount24h),
      summary:
        powershellEventCount24h > 0
          ? `${powershellEventCount24h} Windows PowerShell events were found in the last 24 hours.`
          : "No Windows PowerShell events were found in the last 24 hours.",
      status: powershellEventCount24h >= 8 ? "watch" : "good",
      detail: makeDetail(
        "This counts events in the Windows PowerShell log to show scripting activity volume.",
        powershellEventCount24h > 0
          ? `Windows recorded ${powershellEventCount24h} recent PowerShell engine events.`
          : "The Windows PowerShell log did not return recent engine events during the last 24 hours.",
        powershellEventCount24h > 0 ? `Most recent PowerShell event was seen at ${powershellLatestTime}.` : "Checked the last 24 hours.",
        "Medium confidence because event volume alone does not prove something is malicious.",
      ),
    },
    {
      id: "startup-items",
      section: "Trust",
      title: "Startup entries",
      value: String(startupEntries.length),
      summary:
        startupEntries.length > 0
          ? `${startupEntries.length} startup entries were found from Run keys and startup folders.`
          : "No startup entries were found from the startup locations checked.",
      status: startupWatchCount >= 4 ? "watch" : "good",
      detail: makeDetail(
        "This lists applications configured to launch automatically when Windows starts.",
        startupEntries.length > 0
          ? startupEntries.map((item) => `${item.name} from ${item.source}`).join(". ")
          : "No startup entries were returned from registry Run keys or startup folders.",
        startupEntries.find((entry) => entry.lastWriteTime)
          ? `Latest startup timestamp seen at ${formatDateTime(startupEntries.find((entry) => entry.lastWriteTime)?.lastWriteTime)}.`
          : "Collected from current startup locations.",
        "Medium confidence because some apps start from scheduled tasks or services instead.",
      ),
    },
    {
      id: "recent-apps",
      section: "Trust",
      title: "Recently installed software",
      value: String(installedApps.length),
      summary:
        installedApps.length > 0
          ? `Most recent software includes ${installedApps.slice(0, 3).map((item) => item.name).join(", ")}.`
          : "No installed software list was returned from the uninstall registry keys.",
      status: hasFreshInstall ? "watch" : "good",
      detail: makeDetail(
        "This reads uninstall registry entries and sorts them by install date.",
        installedApps.length > 0
          ? installedApps.map((item) => `${item.name} (${item.installedOn})`).join(". ")
          : "Windows did not return recent installed software metadata for this snapshot.",
        "Collected from uninstall registry entries during this snapshot.",
        "Medium confidence because some installers write incomplete dates or skip registration.",
      ),
    },
  ];

  const eventTimeline: TimelineItem[] = toArray(timelineRaw)
    .slice(0, 4)
    .map((item, index) => ({
      id: `event-${index}`,
      title: item.ProviderName ? `${item.ProviderName} event ${item.Id || ""}`.trim() : `Windows event ${index + 1}`,
      summary:
        item.Id === 403
          ? "PowerShell engine state changed on this device."
          : item.LevelDisplayName
            ? `${item.LevelDisplayName} event recorded by Windows.`
            : "Windows recorded a local event.",
      time: formatDateTime(item.TimeCreated),
      status: item.Id === 403 ? "watch" : "good",
      detail: makeDetail(
        "This timeline item comes from recent Windows event log activity on your laptop.",
        item.ProviderName
          ? `${item.ProviderName} wrote event ID ${item.Id || "unknown"} to the local event log.`
          : "A local Windows provider wrote this event, but the provider name was unavailable.",
        item.TimeCreated ? `Event time: ${formatDateTime(item.TimeCreated)}.` : "No event time was returned.",
        "High confidence that the event exists locally; medium confidence for risk interpretation.",
      ),
    }));

  const timeline: TimelineItem[] = [
    {
      id: "timeline-firewall",
      title: allFirewallEnabled ? "Firewall profiles confirmed on" : "Firewall profile needs review",
      summary: allFirewallEnabled
        ? "Windows reports the firewall is on across the checked profiles."
        : "At least one checked firewall profile is off or unavailable.",
      time: formatDateTime(new Date().toISOString()),
      status: (allFirewallEnabled ? "good" : "risk") as SecurityStatus,
      detail: cards[1].detail,
    },
    {
      id: "timeline-logins",
      title: failedLoginCount24h > 0 ? "Recent failed sign-in activity detected" : "No failed sign-ins in last 24 hours",
      summary:
        failedLoginCount24h > 0
          ? `${failedLoginCount24h} sign-in failures were seen in the Security log.`
          : "The local Security log did not show failed sign-ins in the last day.",
      time: failedLoginCount24h > 0 ? failedLoginLastSeen : formatDateTime(new Date().toISOString()),
      status: (failedLoginCount24h >= 5 ? "risk" : failedLoginCount24h > 0 ? "watch" : "good") as SecurityStatus,
      detail: cards[2].detail,
    },
    ...eventTimeline,
  ].slice(0, 6);

  const overallStatus = getOverallStatus(cards);
  const score = getScore(cards);
  const overviewHeadline =
    overallStatus === "risk"
      ? "Your laptop needs attention in a few security areas."
      : overallStatus === "watch"
        ? "Your laptop looks mostly healthy, with a few things worth checking."
        : "Your laptop looks healthy based on the local signals that were checked.";

  const overviewExplanation = [
    allFirewallEnabled
      ? "Windows firewall profiles appear to be enabled."
      : "At least one firewall profile needs review.",
    trustedAntivirus
      ? `${antivirus[0]?.name || "Antivirus"} appears active.`
      : "An active antivirus provider could not be fully confirmed.",
    failedLoginCount24h > 0
      ? `${failedLoginCount24h} failed sign-ins were recorded in the last 24 hours.`
      : "No failed sign-ins were recorded in the last 24 hours.",
    startupEntries.length > 0
      ? `${startupEntries.length} startup entries were detected from common startup locations.`
      : "No startup entries were detected in the common locations checked.",
  ].join(" ");

  return {
    generatedAt: new Date().toISOString(),
    deviceName: os.CSName || "This PC",
    osName: os.Caption || "Windows",
    osVersion: os.Version || "Unknown",
    lastBootTime: formatDateTime(os.LastBootUpTime),
    antivirus,
    firewallProfiles,
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

