import type { Finding } from "./api";

// A scripted, click-only conversation — not a real AI integration. The
// project's own brief keeps an "AI assistant grounded in scan data" out
// of v1 scope on purpose; this is a simulated preview of what that could
// feel like, not that feature. Answers are templated strings, not model
// output, but they pull real numbers from whatever findings are
// currently loaded, so the preview is at least grounded in real data
// rather than fully made up.
//
// There's no free-text input by design: every turn is the user picking
// one of a fixed set of question chips, which is both simpler to build
// convincingly and honest about what this actually is.

export interface ChatContext {
  findings: Finding[];
  hostnames: string[];
}

export interface ChatNode {
  id: string;
  question: string;
  answer: (ctx: ChatContext) => string;
  followUps: string[];
}

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }
  return counts;
}

function countByStatus(findings: Finding[]) {
  let fixed = 0;
  let noFixAvailable = 0;
  let unknown = 0;
  for (const f of findings) {
    if (f.status === "fixed") fixed++;
    else if (f.status === "will_not_fix" || f.status === "end_of_life") noFixAvailable++;
    else unknown++;
  }
  return { fixed, noFixAvailable, unknown };
}

function worstHosts(findings: Finding[], limit = 3): string[] {
  const scores = new Map<string, number>();
  for (const f of findings) {
    scores.set(f.host, (scores.get(f.host) ?? 0) + (SEVERITY_WEIGHT[f.severity] ?? 0));
  }
  return [...scores.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([host]) => host);
}

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

export const ROOT_QUESTIONS = ["risk-posture", "critical-count", "worst-hosts", "audit-ready"];

export const CHAT_NODES: Record<string, ChatNode> = {
  "risk-posture": {
    id: "risk-posture",
    question: "What's our overall risk posture right now?",
    answer: (ctx) => {
      if (ctx.findings.length === 0) {
        return "No findings are on record right now — either nothing has been scanned yet, or your infrastructure came back clean on the last scan.";
      }
      const counts = countBySeverity(ctx.findings);
      const hostCount = ctx.hostnames.length;
      const total = ctx.findings.length;
      const summary = `Across ${hostCount} ${plural(hostCount, "host")} and ${total} total ${plural(total, "finding")}, you have ${counts.CRITICAL} critical, ${counts.HIGH} high, ${counts.MEDIUM} medium, and ${counts.LOW} low severity findings.`;
      const take =
        counts.CRITICAL > 0
          ? ` The ${counts.CRITICAL} critical ${plural(counts.CRITICAL, "finding")} ${counts.CRITICAL === 1 ? "is" : "are"} where I'd look first — these map to known, actively tracked CVEs, not theoretical risk.`
          : " With no critical findings outstanding, your immediate exposure is lower, though the high and medium findings still deserve a remediation plan.";
      return summary + take;
    },
    followUps: ["worst-hosts", "prioritize"],
  },
  "critical-count": {
    id: "critical-count",
    question: "How many critical vulnerabilities do we have?",
    answer: (ctx) => {
      const counts = countBySeverity(ctx.findings);
      if (counts.CRITICAL === 0) {
        return "Zero. None of your currently tracked findings are rated CRITICAL — that's the strongest position to be in heading into an audit.";
      }
      const criticalFindings = ctx.findings.filter((f) => f.severity === "CRITICAL");
      const { fixed } = countByStatus(criticalFindings);
      const lead = `${counts.CRITICAL} ${plural(counts.CRITICAL, "finding")} ${counts.CRITICAL === 1 ? "is" : "are"} rated CRITICAL.`;
      const detail =
        fixed > 0
          ? ` ${fixed} of those already ${fixed === 1 ? "has" : "have"} a published fix available — that's the fastest risk reduction you can get, since there's no reason to delay once a patch exists.`
          : " None of them have a published fix yet, which means compensating controls — network segmentation, reduced exposure — matter more right now than patching.";
      return lead + detail;
    },
    followUps: ["prioritize", "audit-ready"],
  },
  "worst-hosts": {
    id: "worst-hosts",
    question: "Which hosts need the most attention?",
    answer: (ctx) => {
      const worst = worstHosts(ctx.findings);
      if (worst.length === 0) {
        return "There's no finding data to rank hosts by right now.";
      }
      const lead = `Weighting by severity, ${worst[0]} is carrying the heaviest load right now`;
      const rest = worst.length > 1 ? `, followed by ${worst.slice(1).join(" and ")}.` : ".";
      return `${lead}${rest} Starting a remediation sprint on the worst host first usually closes the largest share of your overall risk in the fewest changes.`;
    },
    followUps: ["risk-posture", "prioritize"],
  },
  "audit-ready": {
    id: "audit-ready",
    question: "Are we audit-ready?",
    answer: (ctx) => {
      const total = ctx.findings.length;
      if (total === 0) {
        return "With no findings on record, there's no remediation backlog to show an auditor — just make sure your scan schedule itself is documented. Most frameworks care more about evidence of continuous scanning than about a perfect result.";
      }
      const { fixed, noFixAvailable, unknown } = countByStatus(ctx.findings);
      return `Most frameworks — SOC 2, ISO 27001 — care less about having zero findings and more about evidence of a working process: continuous scanning plus a documented remediation trail. Right now ${fixed} of your ${total} ${plural(total, "finding")} ${fixed === 1 ? "has" : "have"} a fix already applied, ${noFixAvailable} ${noFixAvailable === 1 ? "has" : "have"} no fix available and need a compensating control instead, and ${unknown} ${unknown === 1 ? "is" : "are"} still being tracked. That mix is normal — what an auditor actually wants to see is that someone is working the list.`;
    },
    followUps: ["prioritize", "critical-count"],
  },
  prioritize: {
    id: "prioritize",
    question: "What should we prioritize first?",
    answer: (ctx) => {
      if (ctx.findings.length === 0) {
        return "There's nothing in the queue to prioritize right now.";
      }
      const criticalWithFix = ctx.findings.filter(
        (f) => f.severity === "CRITICAL" && f.status === "fixed",
      ).length;
      const [topHost] = worstHosts(ctx.findings, 1);
      const first =
        criticalWithFix > 0
          ? `the ${criticalWithFix} critical ${plural(criticalWithFix, "finding")} that already ${criticalWithFix === 1 ? "has" : "have"} a fix available`
          : "your highest-severity findings";
      const hostNote = topHost
        ? ` After that, ${topHost} is the single host where further remediation reduces your overall exposure the most.`
        : "";
      return `Start with ${first} — that's the highest-impact, lowest-effort work available.${hostNote}`;
    },
    followUps: ["risk-posture", "audit-ready"],
  },
};
