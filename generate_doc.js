const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak
} = require("docx");
const fs = require("fs");

// ── Palette ─────────────────────────────────────────────────────────────
const NAVY = "0D2137", TEAL = "0A7B83", WHITE = "FFFFFF", LGRAY = "F4F6F9",
      MGRAY = "C8D0DC", DKGRAY = "4A5568", MUTED = "718096", ACCENT = "C0392B";

const bdr = (c = MGRAY) => ({ style: BorderStyle.SINGLE, size: 1, color: c });
const allB = (c) => ({ top: bdr(c), left: bdr(c), bottom: bdr(c), right: bdr(c) });

const sp = (n = 200) => new Paragraph({ spacing: { after: n }, children: [new TextRun("")] });
const pgB = () => new Paragraph({ children: [new PageBreak()] });

function chHead(text) {
  return new Paragraph({
    spacing: { before: 360, after: 160 },
    children: [
      new TextRun({ text, bold: true, size: 28, font: "Inter", color: TEAL }),
    ],
  });
}

function body(text) {
  return new Paragraph({
    spacing: { after: 180, line: 340 },
    children: [
      new TextRun({ text, size: 22, font: "Inter", color: DKGRAY }),
    ],
  });
}

function stageDir(text) {
  return new Paragraph({
    spacing: { after: 100 },
    children: [
      new TextRun({ text: `[${text}]`, italics: true, size: 20, font: "Inter", color: MUTED }),
    ],
  });
}

function sectionHead(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 400, after: 120 },
    children: [
      new TextRun({ text, bold: true, size: 26, font: "Inter", color: NAVY }),
    ],
  });
}

function qHead(q) {
  return new Paragraph({
    spacing: { before: 280, after: 80 },
    children: [
      new TextRun({ text: q, bold: true, size: 22, font: "Inter", color: TEAL }),
    ],
  });
}

function partTitle(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 500, after: 200 },
    children: [
      new TextRun({ text, bold: true, size: 32, font: "Inter", color: NAVY }),
    ],
  });
}

// ── Cover Page ──────────────────────────────────────────────────────────
const coverRows = [
  ["Student", "Stephanas Osanebi Odogu  ·  2023/B/CYB/0135"],
  ["Supervisor", "Dr. Oluwasegun Ishaya Adelaiye"],
  ["Institution", "MIVA Open University, Abuja  ·  Department of Cybersecurity"],
  ["Session", "2026 / 2027"],
];

function coverTable() {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: coverRows.map(([k, v]) =>
      new TableRow({
        children: [
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            borders: allB(LGRAY),
            shading: { type: ShadingType.SOLID, color: LGRAY },
            children: [new Paragraph({ children: [new TextRun({ text: k, bold: true, size: 20, font: "Inter", color: NAVY })] })],
          }),
          new TableCell({
            width: { size: 75, type: WidthType.PERCENTAGE },
            borders: allB(LGRAY),
            children: [new Paragraph({ children: [new TextRun({ text: v, size: 20, font: "Inter", color: DKGRAY })] })],
          }),
        ],
      })
    ),
  });
}

// ═══════════════════════════════════════════════════════════════════════
//  PART A — THE 10-MINUTE DEFENCE SPEECH
// ═══════════════════════════════════════════════════════════════════════
const speechSections = [
  // ── Slide 1: Opening (~30 seconds) ───────────────────────────────
  {
    heading: "Opening (Slide 1) — ~30 seconds",
    stage: "Stand, make eye contact, speak slowly.",
    paragraphs: [
      "Good morning / afternoon. My name is Stephanas Osanebi Odogu, matric number 2023 slash B slash CYB slash 0135. My supervisor is Dr. Oluwasegun Ishaya Adelaiye.",
      "Today I'm presenting my final year project: an AI-based Network Intrusion Detection and Anomaly Detection System. I'll walk you through the problem, how the system works, the results I got, and what I learned along the way.",
    ],
  },

  // ── Slide 2: The Problem (~60 seconds) ────────────────────────────
  {
    heading: "The Problem (Slide 2) — ~60 seconds",
    paragraphs: [
      "Traditional security tools like Snort and Suricata rely on signatures — they match traffic against known attacks. If an attack is new or modified, they miss it.",
      "Anomaly detection is the alternative — learn what normal looks like and flag anything unusual. But the trade-off is false alarms. On a busy network, too many false positives make the system unusable.",
      "There's also a practical gap. Most academic research stops at accuracy scores in a notebook. Very few actually build a working system with live capture, real-time inference, and a dashboard. That gap is what this project closes.",
    ],
  },

  // ── Slides 3–4: Research Questions & Objectives (~45 seconds) ────
  {
    heading: "Research Questions & Objectives (Slides 3–4) — ~45 seconds",
    paragraphs: [
      "I structured the project around five research questions, each mapping to an objective.",
      "RQ1: does combining three models beat any one alone? RQ2: can one feature set serve both training and live traffic? RQ3: can it detect attacks in real time? RQ4: is the dashboard usable? RQ5: how well do benchmark results match live results?",
      "I'll come back to all of these when I present the results.",
    ],
  },

  // ── Slide 5: Literature Review (~40 seconds) ─────────────────────
  {
    heading: "Literature Review (Slide 5) — ~40 seconds",
    paragraphs: [
      "Many papers propose strong detection methods — Isolation Forest, XGBoost, autoencoders — but they're tested in isolation. The datasets exist, but each uses a different feature schema. No one has put all the pieces together into a deployable, live-validated system.",
      "So my contribution isn't a new algorithm — it's the integration, proving these components can work together end-to-end.",
    ],
  },

  // ── Slide 6: System Architecture (~60 seconds) ───────────────────
  {
    heading: "System Architecture (Slide 6) — ~60 seconds",
    stage: "Point at the diagram as you speak — walk through the four layers.",
    paragraphs: [
      "The system has four layers, each running in its own Docker container.",
      "First, the Capture Layer. A Python sensor built with Scapy sits on the network interface, captures packets, groups them into bidirectional flows based on the five-tuple, and extracts forty-four features from each flow.",
      "Second, the Processing Layer. The feature vector is published to Apache Kafka, which acts as a buffer. On the other side, the inference engine runs all three machine-learning models and assigns a severity level using a meta-fusion layer.",
      "Third, the Persistence Layer. Each alert is enriched with GeoIP location data, checked against Redis for duplicates within a five-minute window, and stored in TimescaleDB.",
      "Fourth, the Presentation Layer. A FastAPI backend serves the data, and a React dashboard shows a live alert feed, severity charts, geographic threat map, and a triage interface for analysts.",
    ],
  },

  // ── Slide 7: ML Pipeline (~60 seconds) ───────────────────────────
  {
    heading: "The Machine Learning Pipeline (Slide 7) — ~60 seconds",
    paragraphs: [
      "Why three models? Because each sees the problem differently.",
      "Isolation Forest is unsupervised — it doesn't need labelled attacks. It learns what normal traffic looks like and flags anything that stands out. This is how the system can catch unknown attacks.",
      "XGBoost is supervised — it's trained on labelled attack categories, so it can actually tell you what type of attack it thinks it's seeing: DoS, brute force, port scan, and so on.",
      "The LSTM Autoencoder looks at sequences of ten consecutive flows from the same source IP. It catches slow attacks that look normal flow-by-flow but form a suspicious pattern over time.",
      "These three signals are combined using a simple OR-gate. If any model's confidence crosses its threshold, the alert is raised. I chose this approach because it's transparent and easy to explain.",
    ],
  },

  // ── Slides 8–11: Sequence & Use Case Diagrams (~40 seconds) ──────
  {
    heading: "Sequence & Use Case Diagrams (Slides 8–11) — ~40 seconds",
    paragraphs: [
      "The sequence diagram traces a single packet's journey through the system — from capture through flow reconstruction, inference, deduplication, storage, and finally a WebSocket push to the analyst's browser. The whole process takes under fifty milliseconds.",
      "The use case diagram shows who interacts with the system: the attacker generates traffic, the analyst reviews and triages alerts, the administrator manages deployment, and the ML engineer handles model training. These were included at my supervisor's request to make the system's behaviour explicit.",
    ],
  },

  // ── Slide 12: Datasets & Preprocessing (~40 seconds) ─────────────
  {
    heading: "Datasets & Preprocessing (Slide 12) — ~40 seconds",
    paragraphs: [
      "I trained and evaluated offline using two benchmark datasets: CICIDS2017 with two-point-eight million flows and seven attack families, and UNSW-NB15 with two-point-five million records and nine categories. Using two datasets tests whether the models generalise — not just memorise one environment.",
      "Both datasets have different feature schemas, and neither matches what my live sensor produces. So I had to harmonise them all into one shared forty-four-feature representation. I also applied SMOTE to handle class imbalance and fitted the scaler only on training data to avoid data leakage.",
    ],
  },

  // ── Slide 13: Evaluation Protocol (~40 seconds) ──────────────────
  {
    heading: "Evaluation Protocol (Slide 13) — ~40 seconds",
    paragraphs: [
      "I evaluated the system in two phases. Offline: a held-out twenty-percent test split that was never seen during training, plus an ablation study testing each model alone versus the full ensemble. I used precision, recall, F1, ROC-AUC, and false-positive rate — not just accuracy, because accuracy is misleading on imbalanced data.",
      "Live: I deployed the full Docker stack on a Kali Linux VirtualBox VM and ran six controlled attack scenarios — SYN flood, SSH brute force, port scan, HTTP denial of service, a mixed attack, and a benign control run.",
    ],
  },

  // ── Slides 14–15: Ablation & Per-Category Results (~60 seconds) ──
  {
    heading: "Results — Ablation & Per-Category (Slides 14–15) — ~60 seconds",
    paragraphs: [
      "The key result: the fused ensemble achieved a macro F1-score of zero-point-eight-eight on CICIDS2017 and zero-point-nine-six on UNSW-NB15 — better than any individual model alone. The ensemble gained plus-zero-point-six-four over Isolation Forest alone, plus-zero-point-one-zero over XGBoost alone, and plus-zero-point-three-three over the LSTM alone.",
      "Per-category, Brute Force was strongest at F1 of zero-point-nine-two, and Port Scan recall reached zero-point-nine-nine-seven. The weakest was DDoS at F1 of zero-point-three-seven, because some flooding traffic has flow statistics very similar to legitimate bursts. I flag this as the top priority for future improvement — adding rate-based and entropy features.",
    ],
  },

  // ── Slides 16–17: Live Results & RQ Resolution (~60 seconds) ─────
  {
    heading: "Live Validation & Research Questions (Slides 16–17) — ~60 seconds",
    paragraphs: [
      "Every one of the five live attack scenarios was correctly detected. SYN flood was flagged Critical at eight-point-five milliseconds. SSH brute force was flagged High. Port scan, Critical. HTTP DoS, High. The mixed scenario triggered correct multi-class alerts.",
      "The benign control run produced only two low-severity false positives, both from a background software update, and both were suppressed by Redis deduplication.",
      "Pipeline throughput reached six-hundred-twenty-five flows per second, above my five-hundred target, with a mean latency of eleven-point-two milliseconds.",
      "Against my five research questions: RQ1 through RQ4 all resolve to yes with the evidence I've shown. RQ5 confirmed a benchmark-to-live performance gap, which is itself a useful finding — it proves why live validation matters.",
    ],
  },

  // ── Slide 18: Limitations (~30 seconds) ──────────────────────────
  {
    heading: "Limitations (Slide 18) — ~30 seconds",
    paragraphs: [
      "I want to be honest about what this system does not do. It never decrypts TLS traffic — detection relies on flow metadata only. It's network-only — no host-level monitoring. Benchmark datasets don't perfectly represent real-world traffic. The fusion thresholds are tuned for this validation data and would need recalibration per network. And GeoIP is a triage aid, not proof of attacker location.",
    ],
  },

  // ── Slide 19: Conclusion (~30 seconds) ───────────────────────────
  {
    heading: "Conclusion & Contributions (Slide 19) — ~30 seconds",
    paragraphs: [
      "To bring it together: this project shows that a layered ensemble — unsupervised, supervised, and temporal detection — measurably outperforms any single model. It delivers a fully containerised, open-source system that goes from raw packet to analyst-ready alert in under fifty milliseconds. And it provides a live validation methodology that most published work doesn't attempt.",
    ],
  },

  // ── Slide 20: Recommendations & Future Work (~25 seconds) ────────
  {
    heading: "Recommendations & Future Work (Slide 20) — ~25 seconds",
    paragraphs: [
      "For anyone deploying this, my main recommendation is: always recalibrate the confidence thresholds on your local traffic before going live. For future work, the top priority is improving DDoS detection with entropy and connection-rate features. Beyond that: online incremental learning to handle concept drift, IPv6 support, and adding a SHAP explainability layer so analysts can see why a specific alert was raised.",
    ],
  },

  // ── Slide 21: Closing (~15 seconds) ──────────────────────────────
  {
    heading: "Closing (Slide 21) — ~15 seconds",
    paragraphs: [
      "That concludes my presentation. Thank you for your time — I'm happy to take any questions the panel may have.",
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════════
//  PART B — ANTICIPATED PANEL QUESTIONS (Grouped by topic)
// ═══════════════════════════════════════════════════════════════════════
const qaGroups = [
  {
    group: "A. Project Overview & Motivation",
    items: [
      {
        q: "Q1. In one sentence, what is your system?",
        a: "It's a real-time, AI-based network intrusion detection system that combines three machine-learning models — unsupervised, supervised, and temporal — to detect known and unknown attacks, with a live dashboard for analyst triage.",
      },
      {
        q: "Q2. Why did you choose this project?",
        a: "I chose it because traditional signature-based IDS tools miss novel attacks, and most academic ML-IDS research stops at offline accuracy without a deployable pipeline. I wanted to build something that actually works end-to-end.",
      },
      {
        q: "Q3. What is the main problem your project solves?",
        a: "Detecting both known and unknown malicious traffic without overwhelming analysts with false alerts. The system addresses this by combining a supervised classifier with unsupervised and temporal detectors, followed by transparent severity-based fusion.",
      },
      {
        q: "Q4. What is the novelty?",
        a: "The novelty is integrative, not algorithmic. I didn't invent Isolation Forest or XGBoost. The contribution is combining these approaches into one reproducible pipeline with a shared feature schema, streaming inference, deduplication, and a dashboard — then validating it both offline and live.",
      },
      {
        q: "Q5. Why not just use Snort or Suricata?",
        a: "Snort and Suricata are excellent at matching known signatures, but they can't detect novel attacks they've never seen before. My system is meant to complement them — in production, I'd recommend running both together.",
      },
      {
        q: "Q6. Is this an IDS or an IPS?",
        a: "It's an IDS. It detects and alerts but doesn't automatically block traffic. Adding prevention capability through firewall or SDN integration is possible but outside the current scope.",
      },
    ],
  },
  {
    group: "B. Research Questions & Objectives",
    items: [
      {
        q: "Q7. Why five research questions?",
        a: "They divide the project into measurable dimensions: model fusion, feature consistency, live detection, analyst usability, and benchmark-versus-live comparison. Each one maps to a specific objective so every piece of work has a traceable purpose.",
      },
      {
        q: "Q8. Have you addressed all five?",
        a: "Yes. RQ1 through RQ4 resolve to a positive with bounded evidence. RQ5 confirmed a measurable benchmark-to-live performance gap, which itself justifies why live validation is necessary.",
      },
    ],
  },
  {
    group: "C. Architecture & Technology",
    items: [
      {
        q: "Q9. Why Docker containers?",
        a: "Docker gives me reproducible, isolated deployments. Each layer — capture, processing, persistence, presentation — runs in its own container, so updating one component doesn't break the others.",
      },
      {
        q: "Q10. Why Kafka?",
        a: "Kafka decouples capture from inference. If a model is slow, the buffer absorbs the delay without creating back-pressure on the network interface. It also provides durability — messages aren't lost if a consumer restarts.",
      },
      {
        q: "Q11. Why TimescaleDB instead of plain PostgreSQL?",
        a: "TimescaleDB is optimised for time-series queries. IDS alerts are inherently time-stamped, and queries like 'show me all critical alerts in the last hour' run much faster on a time-partitioned store.",
      },
      {
        q: "Q12. Why Redis for deduplication?",
        a: "Redis gives sub-millisecond lookups. During a sustained SYN flood, thousands of nearly identical flows arrive per second. Redis lets me suppress duplicates within a five-minute window so the analyst only sees one alert, not thousands.",
      },
      {
        q: "Q13. Why React for the dashboard?",
        a: "React's component model suits a dashboard with live alert feeds, charts, filters, and a threat map — each is an independent, reusable component.",
      },
      {
        q: "Q14. Why Scapy?",
        a: "Scapy gives direct access to packet-level data through Python and is flexible enough for custom flow reconstruction and feature extraction, which prebuilt exporters don't always support.",
      },
    ],
  },
  {
    group: "D. Machine Learning",
    items: [
      {
        q: "Q15. Why Isolation Forest?",
        a: "It doesn't need labelled attacks — it learns what normal looks like and flags outliers. That makes it the component that can catch unknown, zero-day attacks that the supervised model has never been trained on.",
      },
      {
        q: "Q16. Why XGBoost?",
        a: "XGBoost handles structured tabular data very well, learns nonlinear relationships, and provides both class labels and confidence scores — so it can tell you what type of attack it thinks it's seeing.",
      },
      {
        q: "Q17. Why an LSTM Autoencoder?",
        a: "Network attacks aren't always visible in a single flow. The LSTM looks at sequences of ten flows from the same source IP. It learns to reconstruct normal sequences — a high reconstruction error signals an anomaly over time.",
      },
      {
        q: "Q18. Why not use only deep learning?",
        a: "Different attack types have different signatures. One deep-learning model would be a single point of failure. The three models have complementary strengths — unsupervised catches unknowns, supervised classifies knowns, temporal catches slow patterns.",
      },
      {
        q: "Q19. Why an OR-gate for fusion?",
        a: "Transparency and safety. With an OR-gate, an alert is raised if any model is confident enough. This means a novel attack can be caught even if only one model detects it. The trade-off is more false positives, which is why deduplication and severity thresholds matter.",
      },
      {
        q: "Q20. Why not a learned meta-classifier for fusion?",
        a: "A learned fusion layer is possible but makes the decision less transparent and adds another model to train, validate, and explain. For this project, I prioritised interpretability — the panel or an analyst can trace exactly why an alert was raised.",
      },
      {
        q: "Q21. How did you choose the thresholds?",
        a: "They were tuned during training and validation, not on the test set. They balance sensitivity against false positives. They are not universal — any deployment would need local recalibration.",
      },
      {
        q: "Q22. What if all three models disagree?",
        a: "The OR-gate means any single model crossing its threshold is enough to trigger an alert. Disagreement itself is useful information and could be exposed in a future explainability layer.",
      },
    ],
  },
  {
    group: "E. Features, Datasets & Preprocessing",
    items: [
      {
        q: "Q23. Why CICIDS2017?",
        a: "It's widely used in IDS research, contains realistic labelled flows across seven attack families, and provides a standard basis for comparison with other work.",
      },
      {
        q: "Q24. Why use UNSW-NB15 as well?",
        a: "Using two datasets reduces dependence on one traffic-generation methodology. UNSW-NB15 was created in a different environment, so evaluating on both tests whether the models actually generalise.",
      },
      {
        q: "Q25. Why exactly 44 features?",
        a: "The forty-four features are the common set that could be extracted consistently by the live sensor while still covering the most discriminative features from both benchmarks. The goal was: every feature used in training must also be available in real time.",
      },
      {
        q: "Q26. What is data leakage, and how did you avoid it?",
        a: "Data leakage is when test-set information influences training. I avoided it by fitting the StandardScaler only on training data and using a held-out test split that was never seen during training or tuning.",
      },
      {
        q: "Q27. Why SMOTE?",
        a: "The datasets are heavily imbalanced — mostly benign traffic. Without SMOTE, the models could achieve high accuracy by just predicting 'benign' for everything. SMOTE creates synthetic minority examples so underrepresented attack classes get proper training.",
      },
      {
        q: "Q28. Why not report accuracy as your main metric?",
        a: "Accuracy is misleading on imbalanced data. If ninety percent of traffic is benign, predicting 'benign' every time gives ninety percent accuracy but catches zero attacks. I use precision, recall, F1, ROC-AUC, and false-positive rate instead.",
      },
    ],
  },
  {
    group: "F. Results & Evaluation",
    items: [
      {
        q: "Q29. What is your most important result?",
        a: "The fused ensemble outperformed every individual model on both datasets, and all five live attack scenarios were correctly detected. This confirms the architecture works both offline and in real time.",
      },
      {
        q: "Q30. Why is the DDoS F1-score only 0.37?",
        a: "Some DDoS traffic — especially low-rate flooding — has flow statistics that look very similar to legitimate traffic bursts. The current feature set doesn't capture rate or entropy patterns well enough. I flag this as my top priority for future improvement.",
      },
      {
        q: "Q31. Could your results be overfitted?",
        a: "It's a valid concern. I addressed it with a held-out test set, evaluation on two independent datasets, an ablation study, and — most importantly — live validation with traffic the models had never seen before.",
      },
      {
        q: "Q32. Why is your live false-positive rate so low?",
        a: "Two reasons: the ensemble's threshold fusion already filters weak signals, and Redis deduplication collapses repeated alerts. In the benign control run, only two low-severity alerts were generated and both were suppressed.",
      },
    ],
  },
  {
    group: "G. Deployment & Engineering",
    items: [
      {
        q: "Q33. How would you deploy this in a real enterprise?",
        a: "I'd place the sensor on a SPAN port or network TAP, deploy the stack on a dedicated server, do a benign-traffic calibration period first, and integrate alerts into the organisation's existing SIEM or ticketing system.",
      },
      {
        q: "Q34. Does it work on encrypted traffic?",
        a: "Not on payload content — I never decrypt TLS. But it does detect anomalies from flow metadata: packet sizes, timing, connection rates. Many attacks leave detectable patterns even in encrypted sessions.",
      },
      {
        q: "Q35. What are the system requirements?",
        a: "Docker-capable Linux host with at least eight gigabytes of RAM and a network interface supporting promiscuous mode. The full stack uses about four gigabytes under load.",
      },
    ],
  },
  {
    group: "H. Ethics, Limitations & Future",
    items: [
      {
        q: "Q36. What ethical considerations apply?",
        a: "All testing was performed on an isolated, authorised local network. No third-party traffic was captured or analysed. GeoIP data is a triage aid, not surveillance — and the system monitors network flows, not user content.",
      },
      {
        q: "Q37. What is the biggest limitation?",
        a: "The reliance on flow-level metadata without payload inspection. This means encrypted attacks that don't alter flow patterns could potentially evade detection. Adding host-based signals would help address this.",
      },
      {
        q: "Q38. If you had six more months, what would you add first?",
        a: "Three things: better DDoS features — entropy and connection rates. Online incremental learning so the models adapt to changing traffic without full retraining. And SHAP explainability so analysts can see exactly which features triggered each alert.",
      },
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════════
//  PART C — ONE-PAGE CHEAT SHEET
// ═══════════════════════════════════════════════════════════════════════
const cheatSheetRows = [
  ["Models", "Isolation Forest (unsupervised) + XGBoost (supervised) + LSTM Autoencoder (temporal)"],
  ["Fusion", "OR-gate: alert if any model ≥ threshold"],
  ["Thresholds", "IF > 0.65 | LSTM > tuned | XGBoost > 0.70"],
  ["Features", "44 shared features, harmonised across datasets + live sensor"],
  ["Datasets", "CICIDS2017 (2.83M flows) + UNSW-NB15 (2.54M records)"],
  ["Preprocessing", "Clean → Harmonise → SMOTE → StandardScaler (train-only fit)"],
  ["Stack", "Scapy → Kafka → ML Inference → Redis → TimescaleDB → FastAPI → React"],
  ["Containers", "7 Docker microservices"],
  ["Best F1", "0.8793 (CICIDS2017) | 0.9583 (UNSW-NB15)"],
  ["Live", "5/5 attacks detected, <50ms latency, 625 flows/s"],
  ["Weak spot", "DDoS F1 = 0.37 — needs entropy/rate features"],
  ["FP (live)", "2 low-severity, both suppressed by Redis dedup"],
  ["Not done", "No payload inspection, no host-level, no IPv6, thresholds need per-site tuning"],
];

// ═══════════════════════════════════════════════════════════════════════
//  BUILD DOCUMENT
// ═══════════════════════════════════════════════════════════════════════
async function build() {
  const children = [];

  // ── Cover ──
  children.push(sp(600));
  children.push(
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 100 },
      children: [
        new TextRun({ text: "ORAL DEFENCE PREPARATION", bold: true, size: 36, font: "Inter", color: NAVY }),
      ],
    })
  );
  children.push(
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 60 },
      children: [
        new TextRun({ text: "AI-BASED NETWORK INTRUSION & ANOMALY DETECTION SYSTEM", bold: true, size: 26, font: "Inter", color: TEAL }),
      ],
    })
  );
  children.push(
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 300 },
      children: [
        new TextRun({ text: "10-Minute Defence Speech & Panel Question Bank", size: 22, font: "Inter", color: MUTED }),
      ],
    })
  );
  children.push(coverTable());
  children.push(sp(300));
  children.push(
    new Paragraph({
      spacing: { after: 100 },
      children: [
        new TextRun({
          text: "How to use this document: Part A is a 10-minute speech — rehearse it until the ideas feel like your own, not memorised text. Part B has panel questions with concise model answers. Part C is a one-page cheat sheet for last-minute review.",
          italics: true, size: 20, font: "Inter", color: MUTED,
        }),
      ],
    })
  );

  // ── Part A ──
  children.push(pgB());
  children.push(partTitle("Part A: The 10-Minute Defence Speech"));
  children.push(
    body("[Total speaking time target: 10 minutes. Each section has a target time. Practise with a timer — if you're running over, trim the examples, not the key points.]")
  );

  for (const sec of speechSections) {
    children.push(sectionHead(sec.heading));
    if (sec.stage) children.push(stageDir(sec.stage));
    for (const p of sec.paragraphs) {
      children.push(body(p));
    }
  }

  // ── Part B ──
  children.push(pgB());
  children.push(partTitle("Part B: Anticipated Panel Questions & Model Answers"));
  children.push(
    body("[Keep answers direct. Give the core answer first, then expand only if the panel asks for more detail.]")
  );

  for (const g of qaGroups) {
    children.push(sectionHead(g.group));
    for (const item of g.items) {
      children.push(qHead(item.q));
      children.push(body(item.a));
    }
  }

  // ── Part C ──
  children.push(pgB());
  children.push(partTitle("Part C: One-Page Cheat Sheet"));
  children.push(
    body("Pin this page to the inside of your folder. Glance at it before you stand up.")
  );
  children.push(
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: cheatSheetRows.map(([k, v]) =>
        new TableRow({
          children: [
            new TableCell({
              width: { size: 22, type: WidthType.PERCENTAGE },
              borders: allB(MGRAY),
              shading: { type: ShadingType.SOLID, color: LGRAY },
              children: [new Paragraph({ children: [new TextRun({ text: k, bold: true, size: 19, font: "Inter", color: NAVY })] })],
            }),
            new TableCell({
              width: { size: 78, type: WidthType.PERCENTAGE },
              borders: allB(MGRAY),
              children: [new Paragraph({ children: [new TextRun({ text: v, size: 19, font: "Inter", color: DKGRAY })] })],
            }),
          ],
        })
      ),
    })
  );

  // ── Assemble ──
  const doc = new Document({
    styles: {
      default: {
        document: {
          run: { font: "Inter", size: 22, color: DKGRAY },
        },
      },
    },
    sections: [
      {
        headers: {
          default: new Header({
            children: [
              new Paragraph({
                alignment: AlignmentType.RIGHT,
                children: [
                  new TextRun({ text: "Oral Defence Preparation  ·  AI-Based NIDS", size: 16, font: "Inter", color: MUTED }),
                ],
              }),
            ],
          }),
        },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({ text: "Page ", size: 16, font: "Inter", color: MUTED }),
                  new TextRun({ children: [PageNumber.CURRENT], size: 16, font: "Inter", color: MUTED }),
                ],
              }),
            ],
          }),
        },
        children,
      },
    ],
  });

  const buf = await Packer.toBuffer(doc);
  const out = "Oral_Defence_10min.docx";
  fs.writeFileSync(out, buf);
  console.log(`✅  ${out} written (${(buf.length / 1024).toFixed(1)} KB)`);
}

build().catch(err => { console.error(err); process.exit(1); });
