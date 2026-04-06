"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type {
  AskResponse,
  DeviceSnapshot,
  FilePreviewResponse,
  FileScanFinding,
  FileScanResult,
  SandboxPackageResponse,
  SecurityCard,
  TimelineItem,
} from "../lib/types";

type PageKey = "overview" | "protection" | "trusted-apps" | "device-timeline" | "file-scan";

type DetailTarget = {
  title: string;
  subtitle: string;
  detail: {
    what: string;
    how: string;
    when: string;
    confidence: string;
  };
};

const navItems: { key: PageKey; label: string; href: string }[] = [
  { key: "overview", label: "Overview", href: "/overview" },
  { key: "protection", label: "Protection", href: "/protection" },
  { key: "trusted-apps", label: "Trusted Apps", href: "/trusted-apps" },
  { key: "device-timeline", label: "Device Timeline", href: "/device-timeline" },
  { key: "file-scan", label: "File Scan", href: "/file-scan" },
];

function statusLabel(status: DeviceSnapshot["overviewStory"]["status"] | SecurityCard["status"] | TimelineItem["status"]) {
  if (status === "risk") return "Risk";
  if (status === "watch") return "Watch";
  return "Good";
}

function pickFirstDetail(snapshot: DeviceSnapshot | null): DetailTarget | null {
  if (!snapshot?.cards[0]) return null;
  const first = snapshot.cards[0];
  return { title: first.title, subtitle: first.summary, detail: first.detail };
}

function fileCategoryLabel(category: FileScanFinding["category"]) {
  return category === "double_extension" ? "Double extension" : "Suspicious type";
}

function signerLabel(finding: FileScanFinding) {
  if (finding.signerStatus === "signed") return "Signed";
  if (finding.signerStatus === "unsigned") return "Unsigned";
  return "Unknown signer";
}

export default function SafexApp({ currentPage }: { currentPage: PageKey }) {
  const [snapshot, setSnapshot] = useState<DeviceSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [detailTarget, setDetailTarget] = useState<DetailTarget | null>(null);
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [answerSource, setAnswerSource] = useState<AskResponse["source"] | "">("");
  const [asking, setAsking] = useState(false);
  const [fileScan, setFileScan] = useState<FileScanResult | null>(null);
  const [fileScanLoading, setFileScanLoading] = useState(false);
  const [fileScanError, setFileScanError] = useState("");
  const [sandboxBusyId, setSandboxBusyId] = useState("");
  const [sandboxMessage, setSandboxMessage] = useState("");
  const [previewLoadingId, setPreviewLoadingId] = useState("");
  const [previewError, setPreviewError] = useState("");
  const [previewData, setPreviewData] = useState<FilePreviewResponse | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadSnapshot() {
      try {
        setLoading(true);
        setError("");
        const response = await fetch("/api/soc-snapshot", { cache: "no-store" });
        if (!response.ok) throw new Error("Failed to load local device data.");
        const data = (await response.json()) as DeviceSnapshot;
        if (!cancelled) {
          setSnapshot(data);
          setDetailTarget((current) => current || pickFirstDetail(data));
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : "Unable to load local device data.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadSnapshot();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (currentPage !== "file-scan" || fileScan || fileScanLoading) {
      return;
    }

    void refreshFileScan();
  }, [currentPage, fileScan, fileScanLoading]);

  const protectionCards = useMemo(
    () => snapshot?.cards.filter((card) => card.section === "Protection" || card.section === "Behavior") || [],
    [snapshot],
  );

  const trustCards = useMemo(
    () => snapshot?.cards.filter((card) => card.section === "Trust") || [],
    [snapshot],
  );

  async function refreshFileScan() {
    try {
      setFileScanLoading(true);
      setFileScanError("");
      const response = await fetch("/api/file-scan", { cache: "no-store" });
      if (!response.ok) throw new Error("Unable to scan local files.");
      const data = (await response.json()) as FileScanResult;
      setFileScan(data);
    } catch (scanError) {
      setFileScanError(scanError instanceof Error ? scanError.message : "Unable to scan local files.");
    } finally {
      setFileScanLoading(false);
    }
  }

  async function loadPreview(finding: FileScanFinding) {
    try {
      setPreviewLoadingId(finding.id);
      setPreviewError("");
      const response = await fetch(`/api/file-preview?path=${encodeURIComponent(finding.fullPath)}`, { cache: "no-store" });
      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as { error?: string } | null;
        throw new Error(payload?.error || "Unable to open safe preview.");
      }
      const data = (await response.json()) as FilePreviewResponse;
      setPreviewData(data);
    } catch (previewLoadError) {
      setPreviewError(previewLoadError instanceof Error ? previewLoadError.message : "Unable to open safe preview.");
      setPreviewData(null);
    } finally {
      setPreviewLoadingId("");
    }
  }

  async function prepareSandboxPackage(finding: FileScanFinding) {
    try {
      setSandboxBusyId(finding.id);
      setSandboxMessage("");
      const response = await fetch("/api/sandbox-package", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: finding.fullPath }),
      });

      if (!response.ok) throw new Error("Unable to prepare sandbox package.");
      const data = (await response.json()) as SandboxPackageResponse;
      setSandboxMessage(`Sandbox package ready: ${data.sandboxFile}`);
    } catch (sandboxError) {
      setSandboxMessage(sandboxError instanceof Error ? sandboxError.message : "Unable to prepare sandbox package.");
    } finally {
      setSandboxBusyId("");
    }
  }

  async function askAssistant(prompt: string) {
    const cleanPrompt = prompt.trim();
    if (!cleanPrompt) return;

    try {
      setAsking(true);
      const response = await fetch("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: cleanPrompt }),
      });

      if (!response.ok) throw new Error("Unable to get an assistant answer.");

      const data = (await response.json()) as AskResponse;
      setAnswer(data.answer);
      setAnswerSource(data.source);
      setAssistantOpen(true);
    } catch (askError) {
      setAnswer(askError instanceof Error ? askError.message : "Unable to get an assistant answer.");
      setAnswerSource("");
      setAssistantOpen(true);
    } finally {
      setAsking(false);
    }
  }

  function openDetail(title: string, subtitle: string, detail: DetailTarget["detail"]) {
    setDetailTarget({ title, subtitle, detail });
  }

  function renderOverview() {
    if (!snapshot) return null;

    return (
      <section className="content-stack">
        <div className="hero-card">
          <div className="hero-copy">
            <span className="eyebrow">Live overview from your device</span>
            <h1>{snapshot.overviewStory.headline}</h1>
            <p className="lead">{snapshot.overviewStory.explanation}</p>
            <div className="hero-meta compact">
              <div className="meta-pill">
                <span>Device</span>
                <strong>{snapshot.deviceName}</strong>
              </div>
              <div className="meta-pill">
                <span>OS</span>
                <strong>{snapshot.osName}</strong>
              </div>
              <div className="meta-pill">
                <span>Last boot</span>
                <strong>{snapshot.lastBootTime}</strong>
              </div>
            </div>
          </div>

          <div className="hero-side">
            <div className="score-card">
              <span className="tile-label">Security score</span>
              <strong>{snapshot.overviewStory.score}</strong>
              <p>{statusLabel(snapshot.overviewStory.status)}</p>
            </div>
            <button
              type="button"
              className="story-card"
              onClick={() =>
                openDetail("Overview story", snapshot.overviewStory.explanation, {
                  what: "This is Safex's short summary of your device's current security posture.",
                  how: "It combines local Defender, firewall, sign-in, startup, USB, and software signals from this PC.",
                  when: `Snapshot generated at ${new Date(snapshot.generatedAt).toLocaleString("en-IN")}.`,
                  confidence: "Medium to high confidence depending on which Windows sources were available during collection.",
                })
              }
            >
              <span className="tile-label">Overview reasoning</span>
              <strong>Why Safex says this</strong>
              <p>Click to inspect the explanation behind this score and summary.</p>
            </button>
          </div>
        </div>

        <div className="card-grid three-col">
          {snapshot.cards.slice(0, 3).map((card) => (
            <button key={card.id} type="button" className="signal-card" onClick={() => openDetail(card.title, card.summary, card.detail)}>
              <div className="card-topline">
                <span className="tile-label">{card.section}</span>
                <span className={`status-chip ${card.status}`}>{statusLabel(card.status)}</span>
              </div>
              <strong>{card.value}</strong>
              <h3>{card.title}</h3>
              <p>{card.summary}</p>
            </button>
          ))}
        </div>
      </section>
    );
  }

  function renderProtection() {
    if (!snapshot) return null;

    return (
      <section className="content-stack">
        <div className="section-header">
          <div>
            <span className="eyebrow">Protection</span>
            <h2>Defender, firewall, and USB checks</h2>
          </div>
          <button type="button" className="ghost-button" onClick={() => window.location.reload()}>
            Refresh live data
          </button>
        </div>

        <div className="card-grid three-col">
          <div className="mini-card">
            <span className="tile-label">Defender</span>
            <strong>{snapshot.defenderStatus.serviceRunning ? "Running" : "Review"}</strong>
            <p>Real-time protection: {snapshot.defenderStatus.realtimeMonitoring === null ? "Unknown" : snapshot.defenderStatus.realtimeMonitoring ? "On" : "Off"}</p>
          </div>
          <div className="mini-card">
            <span className="tile-label">Firewall</span>
            <strong>{snapshot.firewallProfiles.filter((item) => item.enabled).length}/{snapshot.firewallProfiles.length || 3}</strong>
            <p>Profiles currently enabled.</p>
          </div>
          <div className="mini-card">
            <span className="tile-label">USB</span>
            <strong>{snapshot.usbDevices.length === 0 ? "None" : snapshot.usbDevices.length}</strong>
            <p>{snapshot.usbDevices.length === 0 ? "No external USB device detected." : "External USB devices visible right now."}</p>
          </div>
        </div>

        <div className="card-grid two-col">
          {protectionCards.map((card) => (
            <button key={card.id} type="button" className="signal-card large" onClick={() => openDetail(card.title, card.summary, card.detail)}>
              <div className="card-topline">
                <span className="tile-label">{card.section}</span>
                <span className={`status-chip ${card.status}`}>{statusLabel(card.status)}</span>
              </div>
              <strong>{card.value}</strong>
              <h3>{card.title}</h3>
              <p>{card.summary}</p>
            </button>
          ))}
        </div>
      </section>
    );
  }

  function renderTrustedApps() {
    if (!snapshot) return null;

    return (
      <section className="content-stack">
        <div className="section-header">
          <div>
            <span className="eyebrow">Trusted apps</span>
            <h2>Installed software and startup entries</h2>
          </div>
        </div>

        <div className="list-panel">
          <div className="panel-block">
            <div className="block-header">
              <h3>Installed software trust score</h3>
              <span>{snapshot.installedApps.length} items</span>
            </div>
            <div className="line-list">
              {snapshot.installedApps.map((app) => (
                <button
                  key={`${app.name}-${app.installedOn}`}
                  type="button"
                  className="line-row"
                  onClick={() =>
                    openDetail(app.name, `${app.publisher || "Unknown publisher"} • ${app.installedOn || "Unknown install date"}`, {
                      what: `${app.name} appears in the installed software records for this PC and has a local trust score of ${app.trustScore}.`,
                      how: `${app.trustReason} Version ${app.version || "unknown"} was reported by Windows.`,
                      when: `Installed on ${app.installedOn || "an unknown date"}.`,
                      confidence: "Medium confidence because this is a local trust heuristic, not a malware verdict.",
                    })
                  }
                >
                  <div>
                    <strong>{app.name}</strong>
                    <p>{app.publisher || "Unknown publisher"}</p>
                  </div>
                  <div className="trust-side">
                    <span className={`trust-pill ${app.trustLevel}`}>{app.trustScore}</span>
                    <small>{app.trustLevel}</small>
                  </div>
                </button>
              ))}
            </div>
          </div>

          <div className="panel-block">
            <div className="block-header">
              <h3>Startup entries</h3>
              <span>{snapshot.startupEntries.length} items</span>
            </div>
            <div className="line-list">
              {snapshot.startupEntries.map((entry) => (
                <button
                  key={`${entry.name}-${entry.source}`}
                  type="button"
                  className="line-row"
                  onClick={() =>
                    openDetail(entry.name, entry.source, {
                      what: `${entry.name} is configured to start automatically on this device.`,
                      how: entry.command ? `Windows exposed this startup entry with command: ${entry.command}.` : `Windows exposed this startup entry from ${entry.source}.`,
                      when: entry.lastWriteTime ? `Latest folder timestamp seen at ${new Date(entry.lastWriteTime).toLocaleString("en-IN")}.` : "This snapshot does not include a reliable last modified time for the entry.",
                      confidence: "Medium confidence because some startup behavior can also come from scheduled tasks and services.",
                    })
                  }
                >
                  <div>
                    <strong>{entry.name}</strong>
                    <p>{entry.source}</p>
                  </div>
                  <span>{entry.lastWriteTime ? new Date(entry.lastWriteTime).toLocaleDateString("en-IN") : "Current"}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="panel-block">
            <div className="block-header">
              <h3>Trust summary</h3>
              <span>{trustCards.length} checks</span>
            </div>
            <div className="card-grid single-col compact-grid">
              {trustCards.map((card) => (
                <button key={card.id} type="button" className="signal-card compact" onClick={() => openDetail(card.title, card.summary, card.detail)}>
                  <div className="card-topline">
                    <span className="tile-label">{card.section}</span>
                    <span className={`status-chip ${card.status}`}>{statusLabel(card.status)}</span>
                  </div>
                  <h3>{card.title}</h3>
                  <p>{card.summary}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>
    );
  }

  function renderTimeline() {
    if (!snapshot) return null;

    return (
      <section className="content-stack">
        <div className="section-header">
          <div>
            <span className="eyebrow">Device timeline</span>
            <h2>Recent security-relevant activity</h2>
          </div>
          <button type="button" className="ghost-button" onClick={() => askAssistant("Is my device timeline safe and what does it mean?")}>
            Ask if timeline is safe
          </button>
        </div>

        <div className="timeline-panel">
          {snapshot.timeline.map((item) => (
            <button key={item.id} type="button" className="timeline-row" onClick={() => openDetail(item.title, item.summary, item.detail)}>
              <span className={`timeline-marker ${item.status}`} />
              <div className="timeline-time">{item.time}</div>
              <div className="timeline-copy">
                <div className="timeline-title-row">
                  <strong>{item.title}</strong>
                  <span className={`status-chip ${item.status}`}>{statusLabel(item.status)}</span>
                </div>
                <p>{item.summary}</p>
              </div>
            </button>
          ))}
        </div>
      </section>
    );
  }

  function renderFileScan() {
    return (
      <section className="content-stack">
        <div className="section-header">
          <div>
            <span className="eyebrow">File scan</span>
            <h2>Flagged files from common user folders</h2>
          </div>
          <button type="button" className="ghost-button" onClick={() => refreshFileScan()}>
            {fileScanLoading ? "Scanning..." : "Run scan"}
          </button>
        </div>

        {fileScan ? (
          <div className="scan-summary-row">
            <div className="mini-card">
              <span className="tile-label">Findings</span>
              <strong>{fileScan.findings.length}</strong>
              <p>Files still worth reviewing after Safex filtered out more obvious legitimate signed items.</p>
            </div>
            <div className="mini-card scan-roots-card">
              <span className="tile-label">Scanned roots</span>
              <p>{fileScan.scannedRoots.length > 0 ? fileScan.scannedRoots.join(" • ") : "No common user folders were available for scanning."}</p>
            </div>
          </div>
        ) : null}

        {sandboxMessage ? <div className="notice-card">{sandboxMessage}</div> : null}
        {fileScanError ? <div className="notice-card error">{fileScanError}</div> : null}
        {previewError ? <div className="notice-card error">{previewError}</div> : null}

        <div className="list-panel">
          <div className="panel-block">
            <div className="block-header">
              <h3>Flagged files</h3>
              <span>{fileScan?.findings.length || 0} items</span>
            </div>

            {fileScanLoading ? <p>Scanning Downloads, Desktop, and Documents now...</p> : null}
            {!fileScanLoading && fileScan && fileScan.findings.length === 0 ? (
              <p>No suspicious double-extension or risky script/executable files were found in the scanned folders.</p>
            ) : null}

            <div className="line-list">
              {fileScan?.findings.map((finding) => (
                <div key={finding.id} className="scan-card">
                  <button
                    type="button"
                    className="line-row scan-main"
                    onClick={() =>
                      openDetail(finding.name, finding.fullPath, {
                        what: `${finding.name} was flagged as ${fileCategoryLabel(finding.category).toLowerCase()}.`,
                        how: `${finding.reason} Signer: ${finding.signer}. SHA-256: ${finding.sha256}.`,
                        when: `Last modified ${new Date(finding.modifiedAt).toLocaleString("en-IN")}.`,
                        confidence: "Medium confidence because this is a local review-oriented scan, not executable detonation.",
                      })
                    }
                  >
                    <div>
                      <strong>{finding.name}</strong>
                      <p>{finding.fullPath}</p>
                    </div>
                    <div className="trust-side">
                      <span className={`trust-pill ${finding.category === "double_extension" ? "unknown" : "review"}`}>{fileCategoryLabel(finding.category)}</span>
                      <small>{finding.extension || "no ext"}</small>
                    </div>
                  </button>

                  <div className="scan-meta-grid">
                    <div className="scan-meta-item">
                      <span className="tile-label">Signer</span>
                      <strong>{signerLabel(finding)}</strong>
                      <p>{finding.signer}</p>
                    </div>
                    <div className="scan-meta-item">
                      <span className="tile-label">SHA-256</span>
                      <p className="hash-line">{finding.sha256}</p>
                    </div>
                    <div className="scan-actions">
                      {finding.previewSupported ? (
                        <button type="button" className="ghost-button" onClick={() => loadPreview(finding)} disabled={previewLoadingId === finding.id}>
                          {previewLoadingId === finding.id ? "Opening..." : "Safe preview"}
                        </button>
                      ) : (
                        <span className="scan-note">Preview not available for this file type.</span>
                      )}
                      <button type="button" className="ghost-button sandbox-button" onClick={() => prepareSandboxPackage(finding)} disabled={sandboxBusyId === finding.id}>
                        {sandboxBusyId === finding.id ? "Preparing..." : "Prepare Sandbox Package"}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {previewData ? (
            <div className="panel-block">
              <div className="block-header">
                <h3>Safe preview</h3>
                <span>{previewData.languageHint}</span>
              </div>
              <p>{previewData.path}</p>
              <pre className="preview-box">{previewData.preview}</pre>
              {previewData.truncated ? <p className="scan-note">Preview trimmed to the first 16 KB for safety.</p> : null}
            </div>
          ) : null}
        </div>
      </section>
    );
  }

  function renderActiveView() {
    if (loading) {
      return (
        <div className="loading-shell">
          <div className="loading-card">
            <span className="eyebrow">Collecting live signals</span>
            <h2>Reading your local Windows security data</h2>
            <p>Defender, firewall, USB, startup items, installed apps, sign-ins, and timeline signals are loading now.</p>
          </div>
        </div>
      );
    }

    if (error || !snapshot) {
      return (
        <div className="loading-shell">
          <div className="loading-card error-card">
            <span className="eyebrow">Unable to load</span>
            <h2>Local device data could not be collected</h2>
            <p>{error || "Unknown error."}</p>
          </div>
        </div>
      );
    }

    if (currentPage === "overview") return renderOverview();
    if (currentPage === "protection") return renderProtection();
    if (currentPage === "trusted-apps") return renderTrustedApps();
    if (currentPage === "device-timeline") return renderTimeline();
    return renderFileScan();
  }

  return (
    <main className="app-shell route-shell">
      <aside className="sidebar">
        <div className="brand-card">
          <span className="app-name">Safex</span>
        </div>

        <div className="sidebar-health">
          <span className="tile-label">Local machine</span>
          <strong>{snapshot?.deviceName || "Loading..."}</strong>
          <p>{snapshot ? `${snapshot.osName} • score ${snapshot.overviewStory.score}` : "Preparing live snapshot"}</p>
        </div>

        <nav className="menu" aria-label="Primary">
          {navItems.map((item) => (
            <Link key={item.key} href={item.href} className={currentPage === item.key ? "menu-button active" : "menu-button"}>
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="sidebar-note">
          <span className="tile-label">This PC only</span>
          <p>Each page is focused on one area. Click any item to inspect what, how, when, and confidence.</p>
        </div>
      </aside>

      <section className="workspace">
        <div className="workspace-inner">{renderActiveView()}</div>

        <aside className="detail-panel">
          <div className="detail-card sticky-card">
            <span className="eyebrow">Selected detail</span>
            {detailTarget ? (
              <>
                <h2>{detailTarget.title}</h2>
                <p className="detail-subtitle">{detailTarget.subtitle}</p>
                <div className="qa-list">
                  <div className="qa-item">
                    <span>What</span>
                    <p>{detailTarget.detail.what}</p>
                  </div>
                  <div className="qa-item">
                    <span>How</span>
                    <p>{detailTarget.detail.how}</p>
                  </div>
                  <div className="qa-item">
                    <span>When</span>
                    <p>{detailTarget.detail.when}</p>
                  </div>
                  <div className="qa-item">
                    <span>Are you sure?</span>
                    <p>{detailTarget.detail.confidence}</p>
                  </div>
                </div>
              </>
            ) : (
              <>
                <h2>No item selected</h2>
                <p className="detail-subtitle">Click a card, row, or event to inspect its explanation.</p>
              </>
            )}
          </div>
        </aside>
      </section>

      <button type="button" className="assistant-fab" aria-label="Open Ask Your PC" onClick={() => setAssistantOpen((current) => !current)}>
        AI
      </button>

      {assistantOpen ? (
        <section className="assistant-panel">
          <div className="assistant-header">
            <div>
              <span className="eyebrow">Ask your PC</span>
              <h3>Safex assistant</h3>
            </div>
            <button type="button" className="close-button" onClick={() => setAssistantOpen(false)}>
              Close
            </button>
          </div>

          <div className="assistant-body">
            <div className="prompt-row">
              <button type="button" onClick={() => askAssistant("What should I fix first on this laptop?")}>What should I fix first?</button>
              <button type="button" onClick={() => askAssistant("Is my device timeline safe?")}>Is my timeline safe?</button>
              <button type="button" onClick={() => askAssistant("Which installed app should I review?")}>Which app should I review?</button>
            </div>

            <div className="assistant-form">
              <textarea
                value={question}
                onChange={(event) => {
                  setQuestion(event.target.value);
                  if (answer) {
                    setAnswer("");
                    setAnswerSource("");
                  }
                }}
                placeholder="Ask about this PC, for example: what changed today, is Defender healthy, or which file should I review?"
              />
              <button type="button" onClick={() => askAssistant(question)} disabled={asking}>
                {asking ? "Thinking..." : "Ask"}
              </button>
            </div>

            {answer ? (
              <div className="assistant-answer">
                <div className="answer-head">
                  <span>Answer</span>
                  {answerSource ? <small>{answerSource === "openai" ? "OpenAI API" : "Local grounded fallback"}</small> : null}
                </div>
                <p>{answer}</p>
              </div>
            ) : null}
          </div>
        </section>
      ) : null}
    </main>
  );
}
