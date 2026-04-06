"use client";

import { useEffect, useMemo, useState } from "react";
import type { AskResponse, DeviceSnapshot, SecurityCard, TimelineItem } from "../lib/types";

type TabKey = "overview" | "protection" | "trust" | "timeline";

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

const tabs: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "protection", label: "Protection" },
  { key: "trust", label: "Trusted Apps" },
  { key: "timeline", label: "Device Timeline" },
];

function statusLabel(status: DeviceSnapshot["overviewStory"]["status"] | SecurityCard["status"] | TimelineItem["status"]) {
  if (status === "risk") return "Risk";
  if (status === "watch") return "Watch";
  return "Good";
}

function pickFirstDetail(snapshot: DeviceSnapshot | null): DetailTarget | null {
  if (!snapshot?.cards[0]) {
    return null;
  }

  const first = snapshot.cards[0];
  return {
    title: first.title,
    subtitle: first.summary,
    detail: first.detail,
  };
}

export default function Home() {
  const [snapshot, setSnapshot] = useState<DeviceSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [detailTarget, setDetailTarget] = useState<DetailTarget | null>(null);
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [answerSource, setAnswerSource] = useState<AskResponse["source"] | "">("");
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadSnapshot() {
      try {
        setLoading(true);
        setError("");
        const response = await fetch("/api/soc-snapshot", { cache: "no-store" });
        if (!response.ok) {
          throw new Error("Failed to load local device data.");
        }

        const data = (await response.json()) as DeviceSnapshot;
        if (!cancelled) {
          setSnapshot(data);
          setDetailTarget(pickFirstDetail(data));
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : "Unable to load local device data.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadSnapshot();

    return () => {
      cancelled = true;
    };
  }, []);

  const protectionCards = useMemo(
    () => snapshot?.cards.filter((card) => card.section === "Protection" || card.section === "Behavior") || [],
    [snapshot],
  );

  const trustCards = useMemo(
    () => snapshot?.cards.filter((card) => card.section === "Trust") || [],
    [snapshot],
  );

  async function askAssistant(prompt: string) {
    const cleanPrompt = prompt.trim();
    if (!cleanPrompt) return;

    try {
      setAsking(true);
      const response = await fetch("/api/ask", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ question: cleanPrompt }),
      });

      if (!response.ok) {
        throw new Error("Unable to get an assistant answer.");
      }

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

            <div className="hero-meta">
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
                openDetail(
                  "Overview story",
                  snapshot.overviewStory.explanation,
                  {
                    what: "This story summarizes what your local Windows signals suggest right now.",
                    how: "It combines firewall state, antivirus presence, failed sign-ins, startup entries, and PowerShell activity collected from your laptop.",
                    when: `Snapshot generated at ${new Date(snapshot.generatedAt).toLocaleString("en-IN")}.`,
                    confidence: "Medium to high confidence depending on which Windows data sources were available in this session.",
                  },
                )
              }
            >
              <span className="tile-label">Click for explanation</span>
              <strong>What, how, when, are you sure?</strong>
              <p>Open the detail panel to inspect the reasoning behind this overview.</p>
            </button>
          </div>
        </div>

        <div className="card-grid three-col">
          {snapshot.cards.slice(0, 3).map((card) => (
            <button
              key={card.id}
              type="button"
              className="signal-card"
              onClick={() => openDetail(card.title, card.summary, card.detail)}
            >
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
    return (
      <section className="content-stack">
        <div className="section-header">
          <div>
            <span className="eyebrow">Protection signals</span>
            <h2>What your system is reporting right now</h2>
          </div>
          <button type="button" className="ghost-button" onClick={() => window.location.reload()}>
            Refresh live data
          </button>
        </div>

        <div className="card-grid two-col">
          {protectionCards.map((card) => (
            <button
              key={card.id}
              type="button"
              className="signal-card large"
              onClick={() => openDetail(card.title, card.summary, card.detail)}
            >
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

  function renderTrust() {
    if (!snapshot) return null;

    return (
      <section className="content-stack">
        <div className="section-header">
          <div>
            <span className="eyebrow">Trusted apps and startup memory</span>
            <h2>Software and auto-start entries from your laptop</h2>
          </div>
        </div>

        <div className="list-panel">
          <div className="panel-block">
            <div className="block-header">
              <h3>Recent software</h3>
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
                      what: `${app.name} is listed in this device's uninstall registry entries.`,
                      how: `Windows reported version ${app.version || "unknown"} from ${app.publisher || "an unknown publisher"}.`,
                      when: `Installed on ${app.installedOn || "an unknown date"}.`,
                      confidence: "Medium confidence because some installers do not write complete metadata.",
                    })
                  }
                >
                  <div>
                    <strong>{app.name}</strong>
                    <p>{app.publisher || "Unknown publisher"}</p>
                  </div>
                  <span>{app.installedOn || "Unknown"}</span>
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
                      what: `${entry.name} is configured to launch automatically on this device.`,
                      how: entry.command
                        ? `Windows exposed this startup entry with command: ${entry.command}.`
                        : `Windows exposed this startup entry from ${entry.source}.`,
                      when: entry.lastWriteTime
                        ? `Latest folder timestamp seen at ${new Date(entry.lastWriteTime).toLocaleString("en-IN")}.`
                        : "This snapshot does not include a reliable last modified time for the entry.",
                      confidence: "Medium confidence because startup behavior can also come from scheduled tasks and services.",
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
                <button
                  key={card.id}
                  type="button"
                  className="signal-card compact"
                  onClick={() => openDetail(card.title, card.summary, card.detail)}
                >
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
            <h2>Real recent events from this laptop</h2>
          </div>
          <button
            type="button"
            className="ghost-button"
            onClick={() => askAssistant("Is my device timeline safe and what does it mean?")}
          >
            Ask if timeline is safe
          </button>
        </div>

        <div className="timeline-panel">
          {snapshot.timeline.map((item) => (
            <button
              key={item.id}
              type="button"
              className="timeline-row"
              onClick={() => openDetail(item.title, item.summary, item.detail)}
            >
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

  function renderActiveView() {
    if (loading) {
      return (
        <div className="loading-shell">
          <div className="loading-card">
            <span className="eyebrow">Collecting live signals</span>
            <h2>Reading your local Windows security data</h2>
            <p>Firewall, antivirus state, startup items, installed apps, sign-ins, and timeline signals are loading now.</p>
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

    if (activeTab === "overview") return renderOverview();
    if (activeTab === "protection") return renderProtection();
    if (activeTab === "trust") return renderTrust();
    return renderTimeline();
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-card">
          <span className="app-name">SafePulse</span>
          <p>AI-guided personal SOC for this PC</p>
        </div>

        <div className="sidebar-health">
          <span className="tile-label">Local machine</span>
          <strong>{snapshot?.deviceName || "Loading..."}</strong>
          <p>{snapshot ? `${snapshot.osName} • score ${snapshot.overviewStory.score}` : "Preparing live snapshot"}</p>
        </div>

        <nav className="menu" aria-label="Primary">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              className={activeTab === tab.key ? "menu-button active" : "menu-button"}
              onClick={() => setActiveTab(tab.key)}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-note">
          <span className="tile-label">No raw demo data</span>
          <p>This screen is using your local Windows snapshot. Click any card to inspect what, how, when, and confidence.</p>
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
                <p className="detail-subtitle">Click a card, row, or timeline event to inspect its explanation.</p>
              </>
            )}
          </div>
        </aside>
      </section>

      <button
        type="button"
        className="assistant-fab"
        aria-label="Open Ask Your PC"
        onClick={() => setAssistantOpen((current) => !current)}
      >
        AI
      </button>

      {assistantOpen ? (
        <section className="assistant-panel">
          <div className="assistant-header">
            <div>
              <span className="eyebrow">Ask your PC</span>
              <h3>Bottom-right device assistant</h3>
            </div>
            <button type="button" className="close-button" onClick={() => setAssistantOpen(false)}>
              Close
            </button>
          </div>

          <div className="assistant-body">
            <div className="prompt-row">
              <button type="button" onClick={() => askAssistant("What should I fix first on this laptop?")}>What should I fix first?</button>
              <button type="button" onClick={() => askAssistant("Is my device timeline safe?")}>Is my timeline safe?</button>
              <button type="button" onClick={() => askAssistant("What changed from normal today?")}>What changed today?</button>
            </div>

            <div className="assistant-form">
              <textarea
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                placeholder="Ask about this device, for example: why is this startup app shown, what happened today, or are you sure this is risky?"
              />
              <button type="button" onClick={() => askAssistant(question)} disabled={asking}>
                {asking ? "Thinking..." : "Ask"}
              </button>
            </div>

            <div className="assistant-answer">
              <div className="answer-head">
                <span>Answer</span>
                {answerSource ? <small>{answerSource === "openai" ? "OpenAI API" : "Local grounded fallback"}</small> : null}
              </div>
              <p>{answer || "Ask a question about your PC. The assistant uses your local device snapshot, and if an OpenAI API key is configured it will answer through the API."}</p>
            </div>
          </div>
        </section>
      ) : null}
    </main>
  );
}


