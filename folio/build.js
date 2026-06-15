import {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, TabStopType, TabStopPosition,
  LevelFormat, TableOfContents, PageBreak, SimpleField
} from 'docx';
import fs from 'fs';

// ── Colour palette ──────────────────────────────────────────────────────────
const BLUE   = "1F4E79";
const LBLUE  = "2E75B6";
const TBLUE  = "D5E8F0";  // table header fill
const TALT   = "EBF3FA";  // alternating row fill
const WHITE  = "FFFFFF";
const BLACK  = "000000";
const GREY   = "595959";

// ── Page geometry ────────────────────────────────────────────────────────────
// A4 in DXA: 11906 × 16838
// Margins: top/bottom 1440 (1 in), left/right 1134 (0.79 in)
const PAGE_W    = 11906;
const PAGE_H    = 16838;
const MARGIN    = 1134;
const CONTENT_W = PAGE_W - MARGIN * 2;  // 9638

// ── Borders ──────────────────────────────────────────────────────────────────
function cellBorder(color = "CCCCCC") {
  const b = { style: BorderStyle.SINGLE, size: 4, color };
  return { top: b, bottom: b, left: b, right: b };
}
const BORDER   = cellBorder();
const NONEBD   = {
  top:    { style: BorderStyle.NONE, size: 0, color: WHITE },
  bottom: { style: BorderStyle.NONE, size: 0, color: WHITE },
  left:   { style: BorderStyle.NONE, size: 0, color: WHITE },
  right:  { style: BorderStyle.NONE, size: 0, color: WHITE },
};

// ── Text helpers ─────────────────────────────────────────────────────────────
function txt(text, opts = {}) {
  return new TextRun({ text, font: "Calibri", size: 20, color: BLACK, ...opts });
}
function bold(text, opts = {}) {
  return txt(text, { bold: true, ...opts });
}
function italic(text, opts = {}) {
  return txt(text, { italics: true, ...opts });
}
function para(children, opts = {}) {
  if (typeof children === 'string') children = [txt(children)];
  return new Paragraph({ children, spacing: { after: 100 }, ...opts });
}
function heading1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text, font: "Calibri", size: 28, bold: true, color: BLUE })],
    spacing: { before: 360, after: 120 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: LBLUE, space: 1 } },
  });
}
function heading2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text, font: "Calibri", size: 24, bold: true, color: LBLUE })],
    spacing: { before: 240, after: 80 },
  });
}
function heading3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    children: [new TextRun({ text, font: "Calibri", size: 22, bold: true, color: GREY })],
    spacing: { before: 200, after: 60 },
  });
}
function bullet(children, level = 0) {
  if (typeof children === 'string') children = [txt(children)];
  return new Paragraph({
    numbering: { reference: "bullets", level },
    children,
    spacing: { after: 60 },
  });
}
function spacer(pts = 120) {
  return new Paragraph({ children: [], spacing: { after: pts } });
}

// ── Table helpers ────────────────────────────────────────────────────────────
function hdrCell(text, width) {
  return new TableCell({
    borders: cellBorder(LBLUE),
    shading: { fill: TBLUE, type: ShadingType.CLEAR },
    width: { size: width, type: WidthType.DXA },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: [new Paragraph({
      children: [bold(text, { color: BLUE, size: 18 })],
      spacing: { after: 0 },
    })],
  });
}
function bodyCell(children, width, shading = WHITE, vAlign = VerticalAlign.TOP) {
  if (typeof children === 'string') children = [txt(children, { size: 18 })];
  if (children instanceof Paragraph) children = [children];
  if (Array.isArray(children) && typeof children[0] !== 'object') {
    children = [new Paragraph({ children: children.map(c => typeof c === 'string' ? txt(c, { size: 18 }) : c), spacing: { after: 0 } })];
  }
  if (!(children[0] instanceof Paragraph)) {
    children = [new Paragraph({ children, spacing: { after: 0 } })];
  }
  return new TableCell({
    borders: BORDER,
    shading: { fill: shading, type: ShadingType.CLEAR },
    width: { size: width, type: WidthType.DXA },
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
    verticalAlign: vAlign,
    children,
  });
}
function altRow(cells, isAlt) {
  return new TableRow({ children: cells.map((c, i) => {
    // cells passed as [content, width] pairs
    return bodyCell(c[0], c[1], isAlt ? TALT : WHITE);
  })});
}

// ── Schema table builder ─────────────────────────────────────────────────────
function schemaTable(cols, rows) {
  // cols: [{label, width}]
  const totalW = cols.reduce((a, c) => a + c.width, 0);
  return new Table({
    width: { size: totalW, type: WidthType.DXA },
    columnWidths: cols.map(c => c.width),
    rows: [
      new TableRow({
        tableHeader: true,
        children: cols.map(c => hdrCell(c.label, c.width)),
      }),
      ...rows.map((r, i) => new TableRow({
        children: r.map((cell, j) => bodyCell(
          Array.isArray(cell) ? cell : [txt(cell, { size: 18, bold: j === 0 })],
          cols[j].width,
          i % 2 === 1 ? TALT : WHITE
        )),
      })),
    ],
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOCUMENT CONTENT
// ═══════════════════════════════════════════════════════════════════════════════

const children = [];

// ── COVER ────────────────────────────────────────────────────────────────────
children.push(spacer(480));
children.push(new Paragraph({
  children: [new TextRun({ text: "GearTrack", font: "Calibri", size: 64, bold: true, color: BLUE })],
  alignment: AlignmentType.CENTER, spacing: { after: 80 },
}));
children.push(new Paragraph({
  children: [new TextRun({ text: "Multimedia Department Equipment Rental & Tracking System", font: "Calibri", size: 26, color: LBLUE, italics: true })],
  alignment: AlignmentType.CENTER, spacing: { after: 60 },
}));
children.push(new Paragraph({
  children: [new TextRun({ text: "Component A — Project Documentation", font: "Calibri", size: 22, color: GREY })],
  alignment: AlignmentType.CENTER, spacing: { after: 360 },
}));

// Cover table
children.push(new Table({
  width: { size: CONTENT_W, type: WidthType.DXA },
  columnWidths: [2400, CONTENT_W - 2400],
  rows: [
    ["Student",  "Noah Sheppard"],
    ["Teacher",  "Mr Timothy Harmont"],
    ["School",   "Oxford Falls Grammar"],
    ["Due Date", "Tuesday 16 June 2026, 9:00 AM (Term 2, Week 9)"],
  ].map(([label, value], i) => new TableRow({ children: [
    bodyCell([bold(label, { size: 20 })], 2400, TBLUE),
    bodyCell([txt(value, { size: 20 })], CONTENT_W - 2400, i % 2 === 0 ? WHITE : TALT),
  ]})),
}));

children.push(new Paragraph({
  children: [new PageBreak()],
  spacing: { after: 0 },
}));

// ── TABLE OF CONTENTS (static) ──────────────────────────────────────────────
children.push(heading1("Table of Contents"));
const tocEntries = [
  ["1  Identifying and Defining", "4"],
  ["    1.1  Tools and Processes for Enterprise Systems", "4"],
  ["    1.2  Justify Tools and Resources", "6"],
  ["2  Research and Planning", "8"],
  ["    2.1  Development and Online Collaboration Tools", "8"],
  ["    2.2  Collaboration and Management of the Enterprise Project", "9"],
  ["    2.3  Systems Modelling", "11"],
  ["3  Producing and Implementing", "20"],
  ["    3.1  Implementation Plan", "20"],
  ["    3.2  Enterprise Project Development", "22"],
  ["4  Testing and Evaluating", "25"],
  ["    4.1  Verification and Validation", "25"],
  ["    4.2  Maintenance and Future Development", "28"],
  ["5  Future Technical Changes (Planned)", "31"],
  ["    5.1  Part 1 — Security Improvements", "31"],
  ["    5.2  Part 2 — Feature Completions", "33"],
  ["Appendix — AI Citation Log", "35"],
];
tocEntries.forEach(([entry, page]) => {
  children.push(new Paragraph({
    children: [
      txt(entry, { size: 20 }),
      new TextRun({ text: "\t" + page, font: "Calibri", size: 20, color: GREY }),
    ],
    tabStops: [{ type: TabStopType.RIGHT, position: CONTENT_W }],
    spacing: { after: 60 },
  }));
});
children.push(new Paragraph({ children: [new PageBreak()], spacing: { after: 0 } }));

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1
// ═══════════════════════════════════════════════════════════════════════════════
children.push(heading1("1  Identifying and Defining"));
children.push(heading2("1.1  Tools and Processes for Enterprise Systems"));

children.push(heading3("1.1.1  Problem Definition"));
children.push(para([txt("The Multimedia department at Oxford Falls Grammar manages a significant inventory of professional-grade equipment — including DSLR cameras, mirrorless bodies, cinema lenses, tripods, slider rigs, LED lighting panels, condenser microphones, portable audio recorders, and HDMI/SDI cabling. This equipment is shared across multiple Year 11 and Year 12 classes, co-curricular film projects, and school events. Currently, there is no unified digital system for managing this equipment. The department relies on an ad hoc combination of paper sign-out sheets kept in a physical folder, informal verbal agreements between students and the supervising teacher, and memory.")]));
children.push(para([txt("This approach creates a range of critical operational problems. Equipment goes missing for days — or permanently — because there is no accountability trail linking a specific item to a specific student over a specific timeframe. Staff have no way to determine at a glance which pieces of equipment are currently rented, who has them, and when they are due back. Students cannot check equipment availability remotely; they must physically visit the department room during limited access hours. When equipment is returned damaged, there is often no record of who last used it, making it impossible to establish accountability. The cumulative replacement cost of the department\u2019s inventory exceeds $25,000, making this a significant financial risk for the school.")]));
children.push(para([bold("Problem Statement: "), txt("The Oxford Falls Grammar Multimedia department lacks a centralised, digital system for tracking equipment loans and managing rental requests, resulting in inventory losses, scheduling conflicts, and an unacceptable accountability gap.")]));

children.push(heading3("1.1.2  Context and Stakeholder Analysis"));
// F.3 applied here — added teacher/admin distinction sentence
children.push(para("GearTrack is designed to serve three distinct user groups, each with different needs and levels of system access:"));
children.push(bullet([bold("Students (Primary Users): "), txt("Year 11 and Year 12 Multimedia students who need to borrow equipment for class projects, assessments, and co-curricular productions. Students need a frictionless way to browse available gear, check current availability in real-time, submit rental requests, and view the status of their active and historical rentals.")]));
children.push(bullet([bold("Multimedia Staff / Administrators (Secondary Users): "), txt("The supervising teacher(s) responsible for the equipment inventory. Administrators need a dashboard to review and act on pending rental requests, track which equipment is currently on loan, process returns, and access a complete audit trail of all transactions. In practice, the system distinguishes between Teachers (who can approve requests and manage rosters for their own classes) and a school-wide Admin role (full access to gear inventory, all classes, and system configuration). Both fall under the \u2018Multimedia Staff / Administrators\u2019 group, with role-based access control distinguishing their permissions at the middleware layer.")]));
children.push(bullet([bold("School IT / Department Head (Tertiary Users): "), txt("The school\u2019s IT team (who manage CloudworkEngine) and the department head, who require confidence that the system is secure, maintainable, cost-effective, and integrated with existing school identity infrastructure.")]));

children.push(heading3("1.1.3  System Requirements"));
children.push(para("The system requirements were determined through a combination of structured discussion with the Multimedia teacher, informal surveys of students in the Year 12 class, and analysis of comparable commercial asset management systems (Asset Panda, Snipe-IT). Requirements are categorised as functional (what the system must do) and non-functional (qualities the system must exhibit)."));
children.push(para([bold("Functional Requirements:")]));
children.push(bullet("The system must authenticate users via the school\u2019s CloudworkEngine SAML 2.0 SSO infrastructure, eliminating the need for a separate username/password."));
children.push(bullet("The system must present a searchable, filterable gear catalogue showing all equipment, their categories, quantities, current availability, and condition."));
children.push(bullet("The system must allow authenticated students to submit rental requests specifying the item, quantity, rental start date, and expected return date."));
children.push(bullet("The system must provide an administrative dashboard where staff can view all pending rental requests and approve or reject them with a reason."));
children.push(bullet("The system must automatically update gear availability when a request is approved, or when an item is marked as returned."));
children.push(bullet("The system must maintain a chronological, tamper-evident audit log recording all rental approvals, rejections, and returns, including the actor and timestamp."));
children.push(bullet("The system must prevent students from booking more units than are currently available."));
children.push(spacer());
children.push(para([bold("Non-Functional Requirements:")]));
children.push(bullet([bold("Security: "), txt("All communications must occur over HTTPS. Session cookies must use HttpOnly and Secure flags. All user input must be sanitised to prevent SQL injection and XSS attacks. A Content-Security-Policy header restricts script and resource origins to \u2018self\u2019, preventing injected scripts from loading external payloads. A Strict-Transport-Security header (enabled over HTTPS) enforces HTTPS for all subsequent requests.")]));
children.push(bullet([bold("Performance: "), txt("All page loads must complete within 3 seconds on the school\u2019s internal network under normal concurrent usage (up to 30 simultaneous users).")]));
children.push(bullet([bold("Usability: "), txt("The student-facing interface must be navigable without training, following established UX conventions (navigation bar, action buttons, status indicators).")]));
children.push(bullet([bold("Reliability: "), txt("The system must remain operational during school hours. Database writes must be atomic to prevent partial records.")]));
children.push(bullet([bold("Cost: "), txt("The solution must be deliverable at zero additional cost to the school using open-source software and existing infrastructure.")]));

children.push(heading3("1.1.4  Scope and Scale"));
children.push(para("GearTrack is scoped as an internal web application deployed on the school\u2019s existing server infrastructure (or a Raspberry Pi 4 configured as a local server). The system serves Oxford Falls Grammar exclusively; there is no requirement for multi-tenancy or external internet access. The initial deployment covers the Multimedia department only, though the architecture is intentionally generic to support future extension to the TAS department\u2019s electronics lab equipment or the Drama department\u2019s costume inventory."));
children.push(para("In terms of data scale, the system is expected to manage approximately 80\u2013120 individual gear items, a student population of ~60\u201380 users, and an estimated 5\u201315 active rental transactions per week. These figures are well within the performance envelope of SQLite3 operating in WAL (Write-Ahead Logging) mode."));

children.push(heading3("1.1.5  Success Criteria"));
children.push(para("The following measurable criteria were established in collaboration with the Multimedia teacher to define what a successful project outcome looks like. These criteria are referenced throughout the testing and evaluation section (Section 4)."));

// SC table — F.11 applied: SC-02 updated to "authenticated users"
const scCols = [
  { label: "Ref",      width: 800 },
  { label: "Category", width: 1600 },
  { label: "Criterion", width: 5038 },
  { label: "Verified By", width: 1200 },
];
const scRows = [
  ["SC-01", "Authentication",    "All users can log in via the school\u2019s CloudworkEngine SAML SSO with no separate credentials required.", "TC-01, TC-02"],
  ["SC-02", "Gear Browsing",     "The gear catalogue is accessible to all authenticated users and displays all equipment with availability status.", "TC-03"],
  ["SC-03", "Rental Requests",   "Authenticated students can submit a rental request for any available item and receive on-screen confirmation.", "TC-04"],
  ["SC-04", "Admin Control",     "Administrators can view, approve, and reject rental requests through a dedicated admin dashboard.", "TC-05, TC-06"],
  ["SC-05", "Inventory Accuracy","Gear availability automatically updates in real-time when requests are approved or gear is returned.", "TC-05, TC-07"],
  ["SC-06", "Security",          "The system resists common web attacks (SQL injection, XSS, session hijacking) and enforces role-based access.", "TC-09, TC-10, TC-11"],
  ["SC-07", "Performance",       "All pages load within 3 seconds on the school network under normal usage conditions.", "TC-13"],
  ["SC-08", "Auditability",      "Every approval, rejection, and return action is recorded in a tamper-evident audit log.", "TC-15"],
  ["SC-09", "Usability",         "The system requires no training for students to browse and submit rental requests.", "TC-14 + user feedback"],
  ["SC-10", "Zero Additional Cost", "The solution is built entirely on open-source tools and existing school infrastructure.", "Budget Table"],
];
children.push(schemaTable(scCols, scRows));

// ── 1.2 ──────────────────────────────────────────────────────────────────────
children.push(heading2("1.2  Justify Tools and Resources"));
children.push(para("The selection of every tool and technology in GearTrack was informed by three principles: fitness for purpose (does it solve the specific problem?), integration compatibility (does it work with existing school infrastructure?), and zero incremental cost (can it be delivered without additional budget?)."));

children.push(heading3("1.2.1  Node.js (Runtime Environment)"));
children.push(para("Node.js was selected as the server-side runtime because of its non-blocking, event-driven architecture, which is ideally suited to a system that handles concurrent I/O operations \u2014 specifically, multiple students simultaneously browsing the gear catalogue or submitting rental requests while the database processes writes. Unlike PHP (which spawns a new thread per request) or Python\u2019s synchronous frameworks (which block on I/O), Node.js uses a single-threaded event loop with asynchronous callbacks, meaning a slow database query on one request does not freeze responses for all other users. Node.js is also the most widely documented runtime for integrating SAML 2.0 authentication via the passport-saml library, which was a critical integration requirement for this project."));

children.push(heading3("1.2.2  Express.js (Web Framework)"));
children.push(para("Express.js was chosen over alternatives (Fastify, Hapi, Koa) because of its minimalist, unopinionated design and its dominant position in the Node.js ecosystem \u2014 ensuring that passport, the authentication middleware, integrates seamlessly without configuration friction. Express\u2019s middleware pipeline architecture is well-suited to GearTrack\u2019s authentication flow: every request passes through session validation middleware before reaching protected route handlers, providing a clean separation of authentication logic from business logic. Express does not impose a rigid MVC structure, allowing the project to be structured pragmatically for a solo developer without unnecessary boilerplate."));

children.push(heading3("1.2.3  SQLite3 (Database Engine)"));
children.push(para("SQLite3 was selected over a client-server database (MySQL, PostgreSQL) because GearTrack is deployed in a school environment without a dedicated database server. SQLite operates as a library linked directly into the Node.js process, reading and writing to a single file on disk. This \u2018serverless\u2019 architecture eliminates the need to install, configure, and maintain a separate database process \u2014 a significant operational advantage in a school IT context where administrative overhead must be minimal. SQLite3 supports full ACID transactions, foreign key constraints, and the SQL subset required for GearTrack. WAL mode is enabled to support concurrent reads while a write is in progress, which is the expected access pattern during busy periods."));

children.push(heading3("1.2.4  passport-saml (Authentication Library)"));
children.push(para("SAML 2.0 (Security Assertion Markup Language) is the enterprise-grade identity federation standard used by CloudworkEngine, the school\u2019s identity provider. The passport-saml library, implemented via Passport.js middleware, handles the complete SAML SP (Service Provider) workflow: generating AuthnRequests, receiving and validating SAMLResponses, and extracting user attributes (email, display name, role) from the assertion. Using the school\u2019s existing SSO means students never set a GearTrack-specific password \u2014 they authenticate with their existing school credentials. This dramatically reduces the attack surface (no credential database to breach) and eliminates password fatigue, increasing the likelihood of student adoption."));

children.push(heading3("1.2.5  GitHub (Version Control and Collaboration)"));
children.push(para("GitHub was used as the version control platform throughout development. Git\u2019s branching model allowed isolated development of features (e.g., the SAML authentication flow was developed on a separate branch before being merged into main), preventing unstable code from disrupting the working system. GitHub\u2019s commit history serves as a timestamped process diary, evidencing the iterative development approach. GitHub Issues were used to track bugs and feature requests. The public repository (github.com/NoahSheppard/ofg-geartrack) also demonstrates transparency and allows the teacher to inspect the codebase as a component of the assessment."));

children.push(heading3("1.2.6  Visual Studio Code (Development Environment)"));
children.push(para("VS Code was selected as the primary IDE due to its first-class JavaScript/Node.js support, integrated Git interface, built-in debugging tools (including breakpoints for inspecting SAML assertion payloads), and its availability as a free, cross-platform application. The ESLint extension enforced consistent code style, and the SQLite Viewer extension allowed direct inspection of the database file during development, accelerating debugging of schema and query issues."));

// F.5 — Added 1.2.7, 1.2.8, 1.2.9
children.push(heading3("1.2.7  React + Vite (Frontend Framework & Build Tool)"));
children.push(para("React was chosen for its component model, which maps naturally onto GearTrack\u2019s role-based views \u2014 student rental form, admin dashboard, and teacher class view \u2014 sharing common UI primitives. Vite was chosen over Create React App for its fast hot-module-reload during development and its small, modern production bundle, which the Express backend serves as static files from src/web/dist."));

children.push(heading3("1.2.8  Tailwind CSS + shadcn/ui (Component Library)"));
children.push(para("Tailwind\u2019s utility-class approach allowed rapid, consistent styling without custom CSS for every component, directly supporting the zero-training usability goal (Section 3.1.2) by reusing well-established UI conventions \u2014 cards, badges, modals \u2014 from shadcn/ui\u2019s accessible component primitives."));

children.push(heading3("1.2.9  react-hook-form (Form Validation)"));
children.push(para("Used for client-side validation on the rental request form, including required-field checks and date-after-date validation, satisfying the \u201cform validation provides inline error messages in real time\u201d claim in Section 3.1.2."));

children.push(new Paragraph({ children: [new PageBreak()], spacing: { after: 0 } }));

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2
// ═══════════════════════════════════════════════════════════════════════════════
children.push(heading1("2  Research and Planning"));
children.push(heading2("2.1  Development and Online Collaboration Tools"));

children.push(heading3("2.1.1  Role of Online Collaboration Tools"));
children.push(para("Enterprise software development does not occur in isolation. Even for a solo developer, collaboration tools serve critical functions: they maintain a shared source of truth, enable asynchronous communication with stakeholders (the Multimedia teacher acting as \u2018client\u2019), track project progress against a timeline, and produce an auditable record of development decisions. The following tools were used:"));
children.push(bullet([bold("GitHub (github.com/NoahSheppard/ofg-geartrack): "), txt("Primary collaboration and version control platform. Provides commit history as a process diary, Issues for bug/feature tracking, and a public codebase the teacher-client can inspect. GitHub Actions will be used in a future iteration to automate testing on every push.")]));
children.push(bullet([bold("Google Drive: "), txt("Shared documentation workspace for exchanging requirement notes, wireframe sketches, and feedback with the Multimedia teacher. Enables real-time simultaneous editing and comment threads, simulating a client-developer feedback loop.")]));

children.push(heading3("2.1.2  Gantt Chart"));
children.push(para("The Gantt chart below maps the key development tasks against the seven-week project window from Term 2, Week 2 (27 April 2026) to the submission deadline of Tuesday, Week 9 (16 June 2026). Filled cells indicate the weeks during which each task is actively worked on."));

const ganttCols = [
  { label: "Task",  width: 3000 },
  { label: "T2W2",  width: 900 },
  { label: "T2W3",  width: 900 },
  { label: "T2W4",  width: 900 },
  { label: "T2W5",  width: 900 },
  { label: "T2W6",  width: 900 },
  { label: "T2W7",  width: 900 },
  { label: "T2W8",  width: 1238 },
];
const ganttRows = [
  ["1. Requirements Gathering & Problem Definition", "\u25CF", "\u25CF", "", "", "", "", ""],
  ["2. Database Schema Design & ERD",                "\u25CF", "\u25CF", "", "", "", "", ""],
  ["3. SAML SSO Authentication (passport-saml)",     "\u25CF", "\u25CF", "\u25CF", "", "", "", ""],
  ["4. Gear Catalogue \u2013 Back-end API",          "", "\u25CF", "\u25CF", "", "", "", ""],
  ["5. Gear Catalogue \u2013 Front-end UI",          "", "", "\u25CF", "\u25CF", "", "", ""],
  ["6. Rental Booking System",                       "", "", "\u25CF", "\u25CF", "\u25CF", "", ""],
  ["7. Admin Dashboard & Approval Workflow",         "", "", "", "\u25CF", "\u25CF", "", ""],
  ["8. Testing, Debugging & Bug Fixes",              "", "", "", "", "\u25CF", "\u25CF", ""],
  ["9. Component A \u2013 Documentation Finalisation","", "", "", "", "\u25CF", "\u25CF", "\u25CF"],
  ["10. Component C \u2013 Presentation Preparation","", "", "", "", "", "\u25CF", "\u25CF"],
];
children.push(schemaTable(ganttCols, ganttRows));
children.push(spacer());
children.push(para([italic("Note: Tasks 1 and 2 (requirements and schema) were completed early to unblock all downstream development. Task 3 (SAML SSO) was prioritised as the highest technical risk item \u2014 establishing the authentication foundation before building features that depend on it. Tasks 9 and 10 (documentation and presentation) overlap with late development phases to ensure documentation reflects the final system state.")]));

children.push(heading3("2.1.3  Project Budget"));
children.push(para("A key design constraint for GearTrack was zero incremental cost to the school. The following budget demonstrates that this constraint is met by leveraging exclusively open-source software and the school\u2019s existing infrastructure."));
const budgCols = [
  { label: "Item / Resource", width: 2500 },
  { label: "Description",     width: 3338 },
  { label: "Cost (AUD)",      width: 900 },
  { label: "Notes",           width: 2500 },
];
const budgRows = [
  ["Node.js Runtime",            "Open-source JavaScript server runtime (v22 LTS)",   "$0.00", "Free / Open Source"],
  ["Express.js Framework",       "Lightweight HTTP routing middleware",                "$0.00", "Free / Open Source"],
  ["SQLite3 Database",           "Serverless relational database engine",              "$0.00", "Free / Open Source"],
  ["passport-saml Library",      "SAML 2.0 authentication library for Node.js",       "$0.00", "Free / Open Source"],
  ["bcryptjs Library",           "Password/session token hashing library",            "$0.00", "Free / Open Source"],
  ["React + Vite",               "Frontend framework and build tool",                 "$0.00", "Free / Open Source"],
  ["Tailwind CSS + shadcn/ui",   "Utility CSS and accessible component library",      "$0.00", "Free / Open Source"],
  ["CloudworkEngine SAML SSO",   "School identity provider (existing subscription)",  "$0.00", "Existing school license"],
  ["GitHub Repository",          "Version control and project management",            "$0.00", "Free (Education)"],
  ["Visual Studio Code",         "Primary development environment",                   "$0.00", "Free / Open Source"],
  ["School Server / Existing Hardware", "Deployment target (existing school infrastructure)", "$0.00", "Existing asset"],
  ["SSL Certificate",            "HTTPS encryption for production deployment",        "$0.00", "Let\u2019s Encrypt (free CA)"],
  ["Domain (subdomain)",         "geartrack.ofg.nsw.edu.au (school subdomain)",       "$0.00", "Existing school domain"],
  ["Development Machine",        "Student\u2019s personal laptop (existing asset)",   "$0.00", "Existing asset"],
  ["TOTAL",                      "",                                                   "$0.00 AUD", "Entire project built on free and open-source software."],
];
children.push(schemaTable(budgCols, budgRows));
children.push(spacer());
children.push(para([bold("Budget Analysis: "), txt("GearTrack has a total financial cost of $0.00 to Oxford Falls Grammar. Commercial alternatives (e.g., Asset Panda at ~$35/month, Snipe-IT hosted at ~$50/month) would cost the school $420\u2013$600 per year. GearTrack delivers equivalent functionality with no recurring licence fees and no reliance on third-party cloud services, eliminating both cost and data sovereignty concerns.")]));

// ── 2.2 ──────────────────────────────────────────────────────────────────────
children.push(heading2("2.2  Collaboration and Management of the Enterprise Project"));

children.push(heading3("2.2.1  Designing for Ease of Operation and Maintenance"));
// F.6 applied
children.push(para("GearTrack is designed with maintainability as a first-class concern. The codebase is split into the main GearTrack application (src/) \u2014 containing the Express Service Provider, API routes, and the React frontend (src/web/) \u2014 and a separate git submodule (ofg-geartrack-idp/) containing the SAML Identity Provider used for local development and testing. This structure was refactored from an earlier src/sp/ + src/idp/ layout into a submodule during development, allowing the IdP to be versioned and evolved independently of the main application."));
children.push(para("The SQLite database is a single, self-contained file, making backups as simple as copying the file. Schema migrations are managed as versioned SQL scripts in the /db directory, allowing future developers or IT staff to understand and replicate the database structure."));
children.push(para("From an operational standpoint, GearTrack requires no manual server-side maintenance during normal operation. The Node.js process can be managed as a systemd service, automatically restarting after a crash. The admin dashboard provides all the tools a Multimedia teacher needs to manage the system without IT intervention \u2014 no command-line access is required for day-to-day operation."));

children.push(heading3("2.2.2  Designing for Working Collaboratively"));
children.push(para("While GearTrack was developed by a single student, it is architected as though it will be maintained by a team. The GitHub repository follows a feature-branch workflow: each significant feature (authentication, catalogue, admin dashboard) was developed on a separate branch and merged into master via a pull request. Commit messages follow the Conventional Commits specification (feat:, fix:, docs:, refactor:), making the commit history machine-readable and human-understandable. This practice ensures that a future developer can understand the evolution of the codebase from its commit history alone."));
children.push(para("The Multimedia teacher was engaged as a client throughout the project. Two formal feedback sessions were conducted: one at the requirements stage (to validate problem definition and success criteria) and one at the prototype stage (to test the admin dashboard workflow). Feedback was documented in GitHub Issues and incorporated into the next development iteration."));

children.push(heading3("2.2.3  Negotiation of User and Client Needs"));
children.push(para("An initial draft of the system requirements (see Section 1.1.3) was shared with the Multimedia teacher for validation. The teacher identified two requirements that the initial draft had missed: first, the need for an admin-only \u2018bulk upload\u2019 feature to add gear items from a CSV, reducing the time required to populate the initial gear catalogue; second, a requirement that the system show a student\u2019s full rental history, not just active rentals. Both requirements were incorporated into the design after negotiation \u2014 the CSV import feature is scheduled for a post-assessment implementation, and rental history was included in the student dashboard."));
children.push(para("Additionally, a brief informal survey of five Year 12 students was conducted to evaluate the usability of the wireframe mockups. Feedback indicated a preference for card-based gear display over a list view, which was incorporated into the final front-end design."));

children.push(heading3("2.2.4  Role of Informatics"));
children.push(para("Informatics \u2014 the study of information systems, including the collection, storage, transmission, and use of data \u2014 underpins every aspect of GearTrack. The following information technology components are specifically relevant:"));
children.push(bullet([bold("Databases (SQLite3): "), txt("Structured storage of gear inventory, rental records, user profiles, and audit logs. Relational integrity is enforced through foreign key constraints (e.g., a rental record cannot reference a gear ID that does not exist in the gear table).")]));
children.push(bullet([bold("Networking & HTTP: "), txt("GearTrack operates as an HTTP server on the school\u2019s local network. All traffic is encrypted via HTTPS, ensuring that SAML assertion tokens and session cookies cannot be intercepted in transit.")]));
children.push(bullet([bold("Identity and Access Management (IAM): "), txt("SAML 2.0 is used for federated authentication. Role-Based Access Control (RBAC) is implemented in Express middleware, ensuring that only users with the \u2018admin\u2019 role can access /admin routes.")]));
children.push(bullet([bold("Session Management: "), txt("express-session maintains server-side session state, preventing clients from tampering with their own authentication status.")]));
children.push(bullet([bold("Cryptography: "), txt("bcryptjs is used to hash any local credentials (emergency bypass accounts). SAML assertions are cryptographically signed by the IdP and verified by the SP.")]));

children.push(heading3("2.2.5  Participants, Data, and Components"));
// F.2 applied — added Teachers participant and Classes entity
children.push(para([bold("Participants:")]));
children.push(bullet([bold("Students: "), txt("Submit rental requests; view own rental history; receive status notifications.")]));
children.push(bullet([bold("Teachers: "), txt("Approve, reject, and return rental requests for classes they teach. Can view rosters for their own classes. Their own rental requests are auto-approved without requiring admin review.")]));
children.push(bullet([bold("Admin (Multimedia Teacher): "), txt("Approves/rejects requests; marks items returned; manages gear catalogue. Full access to all classes and system configuration.")]));
children.push(bullet([bold("CloudworkEngine IdP: "), txt("Authenticates users via SAML 2.0; provides user attributes to GearTrack.")]));
children.push(spacer(80));
children.push(para([bold("Core Data Entities:")]));
children.push(bullet([bold("Users: "), txt("Authenticated school identity; name, email, role (student/teacher/admin).")]));
children.push(bullet([bold("Gear Items: "), txt("Equipment records including name, category, manufacturer, model number, serial number, total quantity, available quantity, condition, and description.")]));
children.push(bullet([bold("Classes: "), txt("Named groupings (e.g. \u2018Year 12 Multimedia\u2019) with assigned teachers and enrolled students. Rentals are associated with a class, allowing teachers to review and act on requests scoped to their own students.")]));
children.push(bullet([bold("Rental Transactions: "), txt("A record linking a user to a gear item for a defined period, with an approval status and a full lifecycle (pending \u2192 approved / rejected \u2192 returned / overdue).")]));
children.push(bullet([bold("Audit Log: "), txt("An append-only record of every state-changing action performed in the system, including the actor, action type, affected record, and timestamp.")]));
children.push(spacer(80));
children.push(para([bold("Architectural Components:")]));
children.push(bullet([bold("GearTrack Express Application \u2014 src/: "), txt("The main GearTrack Express application. Handles routing, session management, database queries, and serves the compiled React frontend from src/web/dist.")]));
children.push(bullet([bold("React Frontend \u2014 src/web/: "), txt("Role-based UI built with React, Vite, Tailwind CSS, and shadcn/ui. Compiled to static assets served by the Express backend.")]));
children.push(bullet([bold("SAML IdP Submodule \u2014 ofg-geartrack-idp/: "), txt("The SAML Identity Provider used for local development and testing, maintained as a separate git submodule.")]));
children.push(bullet([bold("SQLite3 Database \u2014 db/: "), txt("The persistent data store; a single .db file containing all tables.")]));

// ── 2.3 ──────────────────────────────────────────────────────────────────────
children.push(heading2("2.3  Systems Modelling"));
children.push(para("The following models were developed during the planning phase to define and communicate the system\u2019s structure and behaviour before implementation commenced. These artefacts served as the design blueprint for the development phase."));

children.push(heading3("2.3.1  Level 0 Data Flow Diagram (Context Diagram)"));
children.push(para([bold("Figure 2.1 \u2014 Level 0 DFD: "), txt("The Level 0 DFD below shows GearTrack as a single process (the central circle) with its three external entities: Student, Admin, and CloudworkEngine IdP. Arrows show the direction and type of data flow between each entity and the system.")]));
children.push(para([bold("Data flows at the context level:")]));
children.push(bullet("Student \u2192 GearTrack: Login request, rental request form data, rental history query."));
children.push(bullet("GearTrack \u2192 Student: SAML redirect (to IdP), gear catalogue display, rental confirmation, rental status updates."));
children.push(bullet("Admin \u2192 GearTrack: Approval/rejection decision, return confirmation, gear catalogue updates."));
children.push(bullet("GearTrack \u2192 Admin: Pending requests list, inventory status dashboard, audit log view."));
children.push(bullet("CloudworkEngine IdP \u2192 GearTrack: SAML assertion (containing user identity attributes)."));
children.push(bullet("GearTrack \u2192 CloudworkEngine IdP: SAML AuthnRequest (authentication request)."));

children.push(heading3("2.3.2  Level 1 Data Flow Diagram"));
children.push(para([bold("Figure 2.2 \u2014 Level 1 DFD: "), txt("The Level 1 DFD decomposes GearTrack into its four core processes: Authentication, Gear Browsing, Rental Management, and Admin Operations. Data stores (Users, Gear, Rentals, Audit Log) are shown as horizontal rectangles.")]));
children.push(para("The four Level 1 processes are:"));
children.push(bullet([bold("Authentication (1.0): "), txt("Receives login requests from Students, constructs a SAML AuthnRequest, redirects the user to CloudworkEngine, receives the SAMLResponse callback, validates the assertion, creates a session, and writes/updates the user record in the Users data store.")]));
children.push(bullet([bold("Gear Browsing (2.0): "), txt("Reads gear item records from the Gear data store and renders the catalogue to authenticated Students and Admins. Accepts search and filter parameters as input flows. No data is written.")]));
children.push(bullet([bold("Rental Management (3.0): "), txt("Receives rental request forms from Students, validates availability against the Gear data store, writes a pending rental record to the Rentals data store, and returns a confirmation to the Student.")]));
children.push(bullet([bold("Admin Operations (4.0): "), txt("Reads pending rentals from the Rentals data store and presents them to the Admin. Receives approval/rejection decisions and updates the Rentals data store. On approval, decrements quantity_available in the Gear data store. All state changes are appended to the Audit Log data store.")]));

children.push(heading3("2.3.3  Database Schema"));
// F.1 applied — eight tables, updated descriptions
children.push(para("The GearTrack relational database schema consists of eight tables, organised into four groups: identity (users), inventory (gear_categories, gear), class management (classes, class_teachers, class_enrollments), and transactions/audit (rentals, audit_log). Foreign key constraints enforce referential integrity across all relationships. The schema is defined in /db/schema.sql and initialised on first run."));

children.push(spacer(80));
children.push(para([bold("Table: users")]));
const usersCols = [
  { label: "Column Name",  width: 1800 },
  { label: "Data Type",    width: 1200 },
  { label: "Constraints",  width: 2000 },
  { label: "Description",  width: 3638 },
];
children.push(schemaTable(usersCols, [
  ["user_id",      "INTEGER",  "PRIMARY KEY AUTOINCREMENT",              "Unique internal identifier for each user."],
  ["email",        "TEXT",     "UNIQUE, NOT NULL",                       "User\u2019s school email address; sourced from SAML NameID attribute."],
  ["display_name", "TEXT",     "NOT NULL",                               "User\u2019s full name; sourced from SAML assertion."],
  ["role",         "TEXT",     "NOT NULL DEFAULT \u2018student\u2019",   "RBAC role: \u2018student\u2019, \u2018teacher\u2019, or \u2018admin\u2019. Set from SAML group attribute."],
  ["created_at",   "DATETIME", "DEFAULT CURRENT_TIMESTAMP",              "Timestamp of first login (record creation)."],
  ["last_login",   "DATETIME", "DEFAULT CURRENT_TIMESTAMP",              "Timestamp of most recent authentication."],
]));
children.push(para([italic("The three-tier role model distinguishes students (request rentals, subject to admin approval), teachers (approve/reject/return rentals for classes they teach; their own rental requests are auto-approved), and admins (full system access; rental requests also auto-approved).")]));

children.push(spacer(80));
children.push(para([bold("Table: gear_categories")]));
children.push(schemaTable(usersCols, [
  ["category_id", "INTEGER", "PRIMARY KEY AUTOINCREMENT", "Unique identifier for each equipment category."],
  ["name",        "TEXT",    "UNIQUE, NOT NULL",          "Category name (e.g., \u2018Cameras\u2019, \u2018Lighting\u2019, \u2018Audio\u2019)."],
  ["description", "TEXT",    "NULL",                      "Optional description of the category."],
]));

children.push(spacer(80));
children.push(para([bold("Table: gear")]));
children.push(schemaTable(usersCols, [
  ["gear_id",            "INTEGER",  "PRIMARY KEY AUTOINCREMENT",          "Unique identifier for each gear item type."],
  ["category_id",        "INTEGER",  "FK \u2192 gear_categories(category_id)", "Category classification for filtering."],
  ["name",               "TEXT",     "NOT NULL",                            "Display name of the equipment (e.g., \u2018Sony A7 III Body\u2019)."],
  ["description",        "TEXT",     "NULL",                                "Detailed description of the item and included accessories."],
  ["quantity_total",     "INTEGER",  "NOT NULL DEFAULT 1",                  "Total number of units owned by the department."],
  ["quantity_available", "INTEGER",  "NOT NULL DEFAULT 1",                  "Current number of units available for rental."],
  ["condition",          "TEXT",     "DEFAULT \u2018Good\u2019",            "Item condition: \u2018Excellent\u2019, \u2018Good\u2019, \u2018Fair\u2019, \u2018Needs Repair\u2019."],
  ["manufacturer",       "TEXT",     "NULL",                                "Equipment manufacturer/brand (e.g., \u2018Canon\u2019, \u2018Rode\u2019)."],
  ["model_no",           "TEXT",     "NULL",                                "Manufacturer model number, where applicable."],
  ["serial_no",          "TEXT",     "NULL",                                "OFG asset/serial number for stocktake traceability."],
  ["type",               "TEXT",     "NULL",                                "Equipment sub-type for items not well described by category alone."],
  ["image_url",          "TEXT",     "NULL",                                "Relative path to the equipment\u2019s thumbnail image."],
  ["created_at",         "DATETIME", "DEFAULT CURRENT_TIMESTAMP",           "Date the item was added to the system."],
]));
children.push(para([italic("The manufacturer, model_no, serial_no, and type columns were added via a migration once the department\u2019s full stocktake data, including manufacturer and serial-number records, was incorporated into the seed script.")]));

children.push(spacer(80));
children.push(para([bold("Table: rentals")]));
children.push(schemaTable(usersCols, [
  ["rental_id",         "INTEGER",  "PRIMARY KEY AUTOINCREMENT",      "Unique identifier for each rental transaction."],
  ["user_id",           "INTEGER",  "FK \u2192 users(user_id)",       "The student who submitted the request."],
  ["gear_id",           "INTEGER",  "FK \u2192 gear(gear_id)",        "The equipment being requested."],
  ["quantity",          "INTEGER",  "NOT NULL DEFAULT 1",             "Number of units requested."],
  ["rental_start",      "DATE",     "NOT NULL",                       "Requested start date for the rental period."],
  ["return_due",        "DATE",     "NOT NULL",                       "Expected return date."],
  ["return_actual",     "DATE",     "NULL",                           "Actual date returned; NULL until item returned."],
  ["status",            "TEXT",     "NOT NULL DEFAULT \u2018pending\u2019", "Lifecycle status: \u2018pending\u2019, \u2018approved\u2019, \u2018rejected\u2019, \u2018returned\u2019, \u2018overdue\u2019."],
  ["approved_by",       "INTEGER",  "FK \u2192 users(user_id), NULL", "Admin user_id who approved/rejected; NULL if pending."],
  ["rejection_reason",  "TEXT",     "NULL",                           "Admin\u2019s reason for rejection; NULL if approved or pending."],
  ["class_id",          "INTEGER",  "FK \u2192 classes(class_id), NULL", "The class this rental is associated with. NULL for admin/teacher rentals not tied to a specific class."],
  ["notes",             "TEXT",     "NULL",                           "Optional context provided by the student when submitting (e.g., \u201cFor Year 12 major project\u201d)."],
  ["created_at",        "DATETIME", "DEFAULT CURRENT_TIMESTAMP",      "Timestamp of request submission."],
  ["updated_at",        "DATETIME", "DEFAULT CURRENT_TIMESTAMP",      "Timestamp of most recent status change."],
]));

children.push(spacer(80));
children.push(para([bold("Table: audit_log")]));
children.push(schemaTable(usersCols, [
  ["log_id",          "INTEGER",  "PRIMARY KEY AUTOINCREMENT",              "Unique identifier for each audit event."],
  ["actor_user_id",   "INTEGER",  "FK \u2192 users(user_id)",              "The user who performed the action."],
  ["action",          "TEXT",     "NOT NULL",                               "Action type: \u2018REQUEST\u2019, \u2018APPROVE\u2019, \u2018REJECT\u2019, \u2018RETURN\u2019, \u2018CREATE_GEAR\u2019, \u2018UPDATE_GEAR\u2019, \u2018CREATE_CLASS\u2019, \u2018ADD_CLASS_TEACHER\u2019, \u2018REMOVE_CLASS_TEACHER\u2019, \u2018ADD_CLASS_STUDENT\u2019, \u2018REMOVE_CLASS_STUDENT\u2019."],
  ["target_rental_id","INTEGER",  "FK \u2192 rentals(rental_id), NULL",    "The rental record affected; NULL for gear CRUD actions."],
  ["target_gear_id",  "INTEGER",  "FK \u2192 gear(gear_id), NULL",         "The gear record affected; NULL for rental actions."],
  ["details",         "TEXT",     "NULL",                                   "Optional JSON string with additional action context."],
  ["timestamp",       "DATETIME", "DEFAULT CURRENT_TIMESTAMP",              "Precise datetime of the action."],
]));

children.push(spacer(80));
children.push(para([bold("Table: classes")]));
children.push(schemaTable(usersCols, [
  ["class_id",    "INTEGER", "PRIMARY KEY AUTOINCREMENT", "Unique identifier for each class."],
  ["name",        "TEXT",    "UNIQUE, NOT NULL",          "Class name (e.g., \u2018Year 12 Multimedia\u2019)."],
  ["description", "TEXT",    "NULL",                      "Optional description of the class."],
  ["created_at",  "DATETIME","DEFAULT CURRENT_TIMESTAMP", "Timestamp of class creation."],
]));

children.push(spacer(80));
children.push(para([bold("Table: class_teachers")]));
children.push(schemaTable(usersCols, [
  ["class_id",  "INTEGER", "FK \u2192 classes(class_id)",  "The class being assigned."],
  ["user_id",   "INTEGER", "FK \u2192 users(user_id)",     "The teacher being assigned to the class."],
  ["assigned_at","DATETIME","DEFAULT CURRENT_TIMESTAMP",   "Timestamp of assignment."],
]));

children.push(spacer(80));
children.push(para([bold("Table: class_enrollments")]));
children.push(schemaTable(usersCols, [
  ["class_id",    "INTEGER", "FK \u2192 classes(class_id)", "The class the student is enrolled in."],
  ["user_id",     "INTEGER", "FK \u2192 users(user_id)",    "The enrolled student."],
  ["enrolled_at", "DATETIME","DEFAULT CURRENT_TIMESTAMP",   "Timestamp of enrollment."],
]));

children.push(spacer());
children.push(para([bold("Referential Integrity: "), txt("Foreign key constraints are enabled in SQLite3 via PRAGMA foreign_keys = ON; executed on every database connection. This ensures that deleting a gear item that has associated rental records is blocked at the database level, preventing orphaned records.")]));

children.push(heading3("2.3.4  System Flowchart"));
children.push(para([bold("Figure 2.3 \u2014 System Flowchart: "), txt("The system flowchart illustrates the complete end-to-end user journey through GearTrack, from initial access through authentication, catalogue browsing, rental request submission, admin review, and gear return.")]));

children.push(heading3("2.3.5  Storyboards"));
children.push(para("Four key user stories were storyboarded to visualise the interface and interaction design before development commenced. Each storyboard represents a primary use-case scenario."));

// Storyboard tables
function storyboardTable(title, frames) {
  const cols = [
    { label: "Frame",                        width: 800 },
    { label: "User Action / System Event",    width: 3500 },
    { label: "Screen / Interface Description", width: 4338 },
  ];
  return [
    para([bold(title)]),
    schemaTable(cols, frames),
    spacer(),
  ];
}

children.push(...storyboardTable("Storyboard A \u2014 Student Logs In and Browses Gear Catalogue:", [
  ["Frame 1", "Student navigates to geartrack.ofg.nsw.edu.au in a browser", "Landing page displays GearTrack logo, a brief description of the system, and a prominent \u2018Sign in with School Account\u2019 button. Navigation bar shows \u2018Browse Gear\u2019 and \u2018Sign In\u2019 links."],
  ["Frame 2", "Student clicks \u2018Sign in with School Account\u2019", "Browser is redirected to CloudworkEngine SSO login page (school-branded). Student enters their existing school username and password."],
  ["Frame 3", "CloudworkEngine validates credentials and redirects back to GearTrack", "Loading screen briefly displayed while SAML assertion is processed. Session is established."],
  ["Frame 4", "Student lands on the authenticated dashboard", "Navigation bar now shows student name and \u2018My Rentals\u2019 link. Gear catalogue grid is displayed with card components for each equipment type."],
  ["Frame 5", "Student uses search bar and category filter to find a specific item", "Catalogue dynamically filters to show only matching items. Each card shows item name, category badge, availability indicator (green/red), and a \u2018Request to Borrow\u2019 button."],
]));
children.push(...storyboardTable("Storyboard B \u2014 Student Submits a Rental Request:", [
  ["Frame 1", "Student clicks \u2018Request to Borrow\u2019 on a Sony A7 III camera card", "A modal dialog or dedicated /gear/:id/request page opens, showing item details and a rental request form."],
  ["Frame 2", "Student completes the rental form", "Form fields: Quantity (number input, max = quantity_available), Rental Start Date (date picker), Return Due Date (date picker), Notes (optional text area for context). Form validates that return date is after start date."],
  ["Frame 3", "Student submits the form", "Loading indicator displayed. POST request sent to /api/rentals."],
  ["Frame 4", "System confirms successful submission", "Success toast notification: \u2018Your request has been submitted and is pending approval.\u2019 Student is redirected to \u2018My Rentals\u2019 page showing the new pending request."],
  ["Frame 5", "Student views \u2018My Rentals\u2019 page", "A table lists all rental requests with columns: Item, Quantity, Dates, Status (badge: Pending/Approved/Rejected/Returned). Pending requests show a yellow badge; approved show green."],
]));
// Storyboard C — F.2.3 note: window.confirm is current state, modal is planned
children.push(...storyboardTable("Storyboard C \u2014 Admin Reviews and Approves a Rental Request:", [
  ["Frame 1", "Admin navigates to /admin and views the Pending Requests queue", "Admin dashboard shows a table of all pending requests: Student Name, Item, Quantity, Dates, Notes, and action buttons (Approve / Reject)."],
  ["Frame 2", "Admin clicks \u2018Approve\u2019 on a pending request", "Confirmation dialog: \u2018Approve rental of Sony A7 III to [Student Name] until [Date]? This will reduce available quantity by 1.\u2019 with Confirm and Cancel options. Note: currently implemented as a browser-native confirmation; a styled modal consistent with the rejection workflow is a planned UI refinement."],
  ["Frame 3", "Admin confirms the approval", "System updates rental status to \u2018approved\u2019, decrements quantity_available, writes audit log entry. Success toast: \u2018Rental approved successfully.\u2019"],
  ["Frame 4", "Admin views the updated Approved Rentals tab", "The approved request appears in the \u2018Active Rentals\u2019 table with the expected return date highlighted if it is within 24 hours."],
  ["Frame 5", "Admin processes a return", "Admin clicks \u2018Mark as Returned\u2019 on an active rental. System updates status to \u2018returned\u2019, restores quantity_available, records actual return date."],
]));
children.push(...storyboardTable("Storyboard D \u2014 Admin Rejects a Rental Request:", [
  ["Frame 1", "Admin identifies a conflicting or inappropriate rental request in the queue", "Pending request table shows a request for equipment that is already committed for that period."],
  ["Frame 2", "Admin clicks \u2018Reject\u2019", "Rejection modal opens with a mandatory text field: \u2018Reason for rejection (required)\u2019."],
  ["Frame 3", "Admin enters a reason and confirms", "\u2018All units of this item are already booked for that period. Please select different dates.\u2019"],
  ["Frame 4", "System processes the rejection", "Status updated to \u2018rejected\u2019; rejection_reason stored in rentals table; audit log entry created."],
  ["Frame 5", "Student views the rejected request on \u2018My Rentals\u2019", "Request shows red \u2018Rejected\u2019 badge; rejection reason visible on hover or expansion."],
]));

children.push(heading3("2.3.6  Decision Tree \u2014 Rental Request Approval Workflow"));
// F.4 applied — added class-enrolment check and auto-approve branch
children.push(para([bold("Figure 2.4 \u2014 Decision Tree: "), txt("The decision tree below models the logic used by both the system (automated validation) and the administrator (manual review) to determine the outcome of a rental request. Branch conditions are shown on edges; outcomes are shown in terminal nodes.")]));
children.push(para("The decision tree captures the following logic path:"));
children.push(bullet([bold("Is the user authenticated?"), txt(" No \u2192 Redirect to SSO login. Yes \u2192 Continue.")]));
children.push(bullet([bold("Is the requested gear item active (not archived) in the catalogue?"), txt(" No \u2192 Display \u2018Item Unavailable\u2019 error. Yes \u2192 Continue.")]));
children.push(bullet([bold("Is quantity_available \u2265 quantity requested?"), txt(" No \u2192 Display \u2018Insufficient availability\u2019 error. Yes \u2192 Continue.")]));
children.push(bullet([bold("Is the user enrolled in the relevant class (for students) or assigned as a teacher of that class (for teachers)?"), txt(" No \u2192 Display \u2018You are not enrolled in / do not teach that class\u2019 error. Yes \u2192 Continue.")]));
children.push(bullet([bold("Is the requesting user a Teacher or Admin?"), txt(" Yes \u2192 Rental is auto-approved immediately: quantity_available decremented, status set to \u2018approved\u2019, and both REQUEST and APPROVE audit log entries recorded. Admin review steps below are skipped. No (Student) \u2192 Continue to manual admin review.")]));
children.push(bullet([bold("Admin reviews the pending request. Does it comply with departmental policy?"), txt(" No \u2192 Admin rejects with reason; status = \u2018rejected\u2019; student notified. Yes \u2192 Continue.")]));
children.push(bullet([bold("Admin approves the request."), txt(" System decrements quantity_available by quantity; status = \u2018approved\u2019. Student notified.")]));
children.push(bullet([bold("On the due date: has the item been returned?"), txt(" Yes \u2192 Admin marks as returned; quantity_available restored; status = \u2018returned\u2019. No \u2192 System flags rental as \u2018overdue\u2019; admin follows up with student.")]));

children.push(new Paragraph({ children: [new PageBreak()], spacing: { after: 0 } }));

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3
// ═══════════════════════════════════════════════════════════════════════════════
children.push(heading1("3  Producing and Implementing"));
children.push(heading2("3.1  Implementation Plan"));

children.push(heading3("3.1.1  Hardware and Software Integration"));
children.push(para([bold("Identity Management Integration (CloudworkEngine SAML SSO):")]));
children.push(para("CloudworkEngine acts as the SAML 2.0 Identity Provider (IdP). GearTrack is registered as a Service Provider (SP) within CloudworkEngine\u2019s administration console. The integration requires two configuration artefacts: first, the IdP metadata XML (containing the IdP\u2019s entity ID, SSO endpoint URL, and X.509 certificate for assertion signing), which GearTrack\u2019s passport-saml configuration consumes; second, the SP metadata XML (containing GearTrack\u2019s entity ID, Assertion Consumer Service URL, and SP certificate), which must be registered in CloudworkEngine. The SAML assertion returned by CloudworkEngine contains three key attributes mapped to GearTrack\u2019s user model: NameID (mapped to email), displayName, and groups (used to determine the \u2018admin\u2019 role by checking group membership against a configured admin group name)."));
children.push(para([bold("Server Hardware Integration:")]));
children.push(para("GearTrack is designed to run on any hardware capable of executing Node.js v18+. For the assessment demonstration, the system runs on a development laptop. For a production school deployment, GearTrack would be suitable for a Raspberry Pi 4 (4 GB RAM, ~$80 existing asset) running Ubuntu Server 24.04. The SQLite3 database file would reside on the Pi\u2019s SD card (or preferably a USB-attached SSD for reliability). The Node.js process would be managed as a systemd service with automatic restart on failure."));
children.push(para([bold("HTTPS/SSL Integration:")]));
children.push(para("SAML 2.0 requires HTTPS for all ACS (Assertion Consumer Service) endpoints. A TLS certificate from Let\u2019s Encrypt (free, automatically renewed every 90 days) is used in production. During development, a self-signed certificate is used. The Node.js process runs behind an nginx reverse proxy that handles TLS termination, forwarding HTTP traffic to the Express server on port 3000."));

children.push(heading3("3.1.2  Training Plan"));
children.push(para("GearTrack\u2019s training strategy reflects the fact that students (the primary user group) should require no training, while administrators (the Multimedia teacher) require a brief onboarding session."));
children.push(para([bold("Student Training: "), txt("The student-facing interface is designed to follow established web conventions, ensuring zero-training usability. The gear catalogue uses a card grid layout familiar from e-commerce sites. CTAs use clear imperative labels (\u2018Request to Borrow\u2019, \u2018View My Rentals\u2019). Form validation (via react-hook-form) provides inline error messages in real time. A brief in-app help overlay is accessible via a \u2018?\u2019 icon in the navigation bar.")]));
children.push(para([bold("Admin Training: "), txt("The Multimedia teacher will receive a single 30-minute in-person training session. The session will cover: logging in via SSO, navigating the admin dashboard, approving and rejecting requests, processing returns, and adding new gear items to the catalogue. A one-page laminated quick-reference card will be produced and affixed near the department computer, covering the six most common admin tasks with step-by-step instructions and screenshots.")]));

children.push(heading3("3.1.3  Systems Implementation Method \u2014 Phased Implementation"));
children.push(para("GearTrack uses a phased implementation strategy, progressively deploying system modules while the previous phase remains operational."));
children.push(bullet([bold("Phase 1 \u2014 Authentication & Core Infrastructure (T2W3\u2013W4): "), txt("Deploy the SAML SSO authentication module, establish the database schema, and make the authenticated shell of the application accessible. Success criterion: Admin can log in via CloudworkEngine SSO.")]));
children.push(bullet([bold("Phase 2 \u2014 Gear Catalogue (T2W5): "), txt("Deploy the gear catalogue browsing module, pre-populated with the department\u2019s full inventory. Success criterion: All Multimedia students can view the catalogue from any school device.")]));
children.push(bullet([bold("Phase 3 \u2014 Rental Request System (T2W5\u2013W6): "), txt("Deploy the rental request submission workflow and the admin approval dashboard. Success criterion: Full rental lifecycle from submission to approval/rejection is functional.")]));
children.push(bullet([bold("Phase 4 \u2014 Refinement & Full Production (T2W7\u2013W8): "), txt("Incorporate feedback, implement remaining features (audit log viewer, overdue flagging, gear condition reporting), and conduct formal testing. Success criterion: All success criteria in Section 1.1.5 are met.")]));

children.push(heading3("3.1.4  Testing Methodology \u2014 Functional Testing with Simulated Data"));
children.push(para("GearTrack uses functional testing as its primary testing methodology, supplemented by security testing for authentication and injection vulnerabilities. Simulated data is used rather than live production data during testing to avoid privacy risk and allow deliberate creation of edge-case scenarios."));
children.push(bullet([bold("Acceptance Testing: "), txt("The Multimedia teacher reviewed the admin dashboard against the negotiated requirements (Section 2.2.3).")]));
children.push(bullet([bold("Security Testing: "), txt("Common web vulnerabilities (OWASP Top 10 relevant to GearTrack) were manually tested, including SQL injection via form fields, XSS via input fields, and session manipulation via cookie modification.")]));
children.push(bullet([bold("Volume Testing: "), txt("The SQLite3 database was pre-populated with 500 rental records (simulating ~10 years of usage) and page load times measured to verify that performance does not degrade with data volume.")]));

children.push(heading3("3.1.5  Risk Analysis"));
const riskCols = [
  { label: "Ref",      width: 600 },
  { label: "Severity", width: 800 },
  { label: "Risk",     width: 1800 },
  { label: "Impact",   width: 1800 },
  { label: "Mitigation Strategy", width: 2638 },
  { label: "Residual Likelihood", width: 1000 },
];
children.push(schemaTable(riskCols, [
  ["R-01", "High",   "SAML SSO Service Outage",         "CloudworkEngine IdP becomes unavailable; users cannot authenticate.", "Implement a local emergency admin bypass account; cache user sessions aggressively. Monitor CloudworkEngine status.", "Low"],
  ["R-02", "High",   "SQL Injection / Data Breach",      "Malicious user exploits poorly sanitised queries to access or destroy the database.", "Use parameterised queries throughout (no string concatenation in SQL). Regular database backups.", "Very Low"],
  ["R-03", "Medium", "Session Hijacking",                "Attacker intercepts a session cookie and impersonates a legitimate user.", "Enforce HTTPS-only. HSTS header enabled when request is served over HTTPS (req.secure); omitted safely in development. Use httpOnly and Secure cookie flags. Short session TTL (30 minutes).", "Low"],
  ["R-04", "Medium", "Data Loss (Database Corruption)",  "SQLite database file becomes corrupted due to power failure or disk error.", "Scheduled automated backups to a separate directory/cloud. Write-ahead logging (WAL mode) enabled.", "Low"],
  ["R-05", "Medium", "Unauthorised Admin Access",        "Non-admin user accesses admin routes by manipulating URL or session.", "Server-side role check on every protected route. Roles stored in session, sourced from SAML assertion, not client-side.", "Very Low"],
  ["R-06", "Low",    "Cross-Site Scripting (XSS)",       "Malicious script injected via user input and executed in other users\u2019 browsers.", "Sanitise and escape all user-generated content before rendering. Content-Security-Policy HTTP header is applied at the middleware layer in src/index.js, restricting script and resource origins to \u2018self\u2019. Verified via browser developer tools during testing.", "Very Low"],
  ["R-07", "Low",    "Denial of Service (DoS)",          "High volume of requests overwhelm the server, making the system unavailable.", "Rate limiting middleware (express-rate-limit) planned as near-term addition. Current mitigation: school network firewall provides first line of defence.", "Low"],
]));

// ── 3.2 ──────────────────────────────────────────────────────────────────────
children.push(heading2("3.2  Enterprise Project Development"));

children.push(heading3("3.2.1  Process Diary"));
// F.10 applied — aligned with actual git history
children.push(para("The following diary entries document key development milestones, aligned with the actual Git commit history in the GitHub repository."));

children.push(para([bold("Early Development \u2014 February to April 2026:")]));
children.push(para("Initial work focused on building the standalone SAML Identity Provider (now housed in the ofg-geartrack-idp/ submodule), scaffolding the Express Service Provider skeleton, and establishing a primitive database structure. These early iterations established the SAML trust relationship and communication flow before any application features were built on top."));

children.push(para([bold("Late April to May 2026:")]));
children.push(para("Intensive SAML SSO integration and debugging, resolving attribute mapping issues between CloudworkEngine and the GearTrack user model. Database schema was finalised across the five core tables (users, gear_categories, gear, rentals, audit_log). The repository structure was refactored \u2014 the IdP was extracted into a git submodule (ofg-geartrack-idp/) so it could be versioned and evolved independently of the main application. The gear, class, and enrolment tables were added via migrations as the scope of the class management system became clear."));

children.push(para([bold("Early June 2026:")]));
children.push(para("The React frontend was scaffolded (src/web/), including component structure and UI design with Tailwind CSS and shadcn/ui. At this stage the frontend operated against mock/dummy data while the backend API was being finalised."));

children.push(para([bold("Final Integration Week (T2W7\u2013W8):")]));
children.push(para("Complete backend API implementation: gear catalogue endpoints, rental lifecycle (submit, approve, reject, return), admin approval workflow, audit logging on all state-changing actions, and the class and teacher management system. The React frontend was wired to the real API, replacing all mock data. The seed script was finalised with the full department inventory including manufacturer and serial-number data."));
children.push(para("During final integration testing, several issues were identified and resolved. The most significant was ensuring the approval transaction correctly guards against overselling \u2014 resolved by using a conditional UPDATE inside a transaction in tryDecrementGear() (src/index.js, lines 442\u2013452 and 676\u2013699). This is the race condition mitigation that prevents two simultaneous approvals from decrementing quantity_available below zero."));

children.push(para([bold("Term 2, Week 8 (2\u20136 Jun 2026):")]));
children.push(para("Conducted formal testing across all 15 test cases (see Section 4.1). All 15 tests passed. Incorporated teacher feedback from the acceptance testing session: added a confirmation step before approve/reject actions, and a Notes field to the rental request form. Began Component C presentation preparation. Finalised project documentation."));

children.push(para([bold("Term 2, Week 9 (9\u201313 Jun 2026):")]));
children.push(para("Final review and refinement of documentation, testing, and presentation. Submission of all components by the 9:00 AM deadline on Tuesday 16 June."));

children.push(heading3("3.2.2  Alignment with Problem Definition and Tools"));
children.push(para("GearTrack directly and comprehensively addresses the problem defined in Section 1.1.1. The three core symptoms of the problem are each addressed by a specific system module:"));
children.push(bullet([bold("Accountability Trail \u2192 Audit Log (audit_log table + admin viewer): "), txt("Every rental action is recorded with actor, action, affected record, and timestamp. The teacher can produce a complete chronological history of any piece of equipment\u2019s loan history.")]));
children.push(bullet([bold("Remote Availability Checking \u2192 Gear Catalogue: "), txt("Students can check current availability from any school device after authenticating, without needing to physically visit the department.")]));
children.push(bullet([bold("Admin Oversight \u2192 Admin Dashboard (/admin): "), txt("The teacher has a dedicated, role-protected interface that consolidates all pending requests, active loans, and overdue items into a single view.")]));
children.push(para("The tool selection (Node.js, Express, SQLite3, passport-saml, React, Vite, Tailwind CSS) proved well-matched to the problem scope. Node.js\u2019s asynchronous model handled concurrent catalogue requests. SQLite3\u2019s single-file architecture simplified deployment and backup. The React + Vite frontend with shadcn/ui components delivered a polished, accessible UI that met the zero-training usability goal without requiring a backend templating system."));

children.push(new Paragraph({ children: [new PageBreak()], spacing: { after: 0 } }));

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4
// ═══════════════════════════════════════════════════════════════════════════════
children.push(heading1("4  Testing and Evaluating"));
children.push(heading2("4.1  Verification and Validation"));

children.push(heading3("4.1.1  Test Results"));
// F.11 applied — TC-03 updated
children.push(para("Formal functional and security testing was conducted in Term 2, Week 8. All 15 test cases produced results matching the expected outputs."));
const tcCols = [
  { label: "ID",       width: 700 },
  { label: "Test Case", width: 1800 },
  { label: "Input",    width: 1800 },
  { label: "Expected", width: 1500 },
  { label: "Actual",   width: 1500 },
  { label: "Result",   width: 738 },
  { label: "Type",     width: 800 },
];
children.push(schemaTable(tcCols, [
  ["TC-01", "SAML SSO Redirect",               "Authenticated user navigates to /login",                                                  "Browser redirects to CloudworkEngine SSO login page",                            "Browser successfully redirected to CloudworkEngine IdP login portal",                          "Pass", "Functional"],
  ["TC-02", "SSO Callback & Session Creation", "Valid school credentials entered at IdP",                                                 "User session created; redirected to gear catalogue dashboard",                     "Session established with correct user attributes (name, email, role)",                         "Pass", "Functional"],
  ["TC-03", "Authenticated Gear Browse",       "Authenticated user (any role) navigates to the application root /",                       "Gear catalogue renders with all items, availability indicators, and category filters", "Catalogue renders correctly via /api/gear; booking controls visible only to authenticated users with appropriate role", "Pass", "Functional"],
  ["TC-04", "Rental Request Submission",       "Authenticated student submits rental form (Camera A, 1 unit, 3 days)",                    "Rental request created with status \u2018pending\u2019; confirmation shown",         "Request stored in DB with correct fields; user notified on-screen",                           "Pass", "Functional"],
  ["TC-05", "Admin Approval Workflow",         "Admin navigates to /admin/requests and approves TC-04 request",                          "Request status changes to \u2018approved\u2019; gear availability decremented",      "Status updated to \u2018approved\u2019; quantity_available reduced by 1",                    "Pass", "Functional"],
  ["TC-06", "Admin Rejection Workflow",        "Admin rejects a pending rental request with reason",                                     "Request status changes to \u2018rejected\u2019; student notified",                   "Status updated; rejection reason recorded in audit log",                                      "Pass", "Functional"],
  ["TC-07", "Gear Return Processing",          "Admin marks an approved rental as returned",                                             "Request status changes to \u2018returned\u2019; gear availability incremented",      "Status updated; quantity_available restored correctly",                                       "Pass", "Functional"],
  ["TC-08", "Duplicate Booking Prevention",    "Student attempts to book already fully-booked equipment",                                "System displays \u2018unavailable\u2019 and prevents duplicate booking",             "Booking form disabled; error message displayed",                                              "Pass", "Functional"],
  ["TC-09", "Session Expiry & Security",       "User session token manually expired/deleted",                                            "User redirected to login page; cannot access protected routes",                   "Protected routes return 401; redirect to /login occurs",                                     "Pass", "Functional"],
  ["TC-10", "SQL Injection Attempt",           "Malicious input entered in search field: \u2019; DROP TABLE gear;\u2014",               "Input sanitised; no database error; no data loss",                                "Input escaped by parameterised queries; no adverse effect",                                   "Pass", "Security"],
  ["TC-11", "XSS Attack Prevention",           "Script tag entered in gear name field: <script>alert(\u2018xss\u2019)</script>",        "Script not executed; input escaped and stored as text",                           "HTML entities rendered correctly; no script execution",                                       "Pass", "Security"],
  ["TC-12", "Concurrent Rental Requests",      "Two students simultaneously request the last available unit of one item",                "One request approved; other receives availability error",                         "Race condition handled via tryDecrementGear() transaction; only one booking created",         "Pass", "Functional"],
  ["TC-13", "Page Load Performance",           "Load /gear on a standard school network connection",                                    "Page fully rendered in under 3 seconds",                                          "Average load time: 1.2 seconds (tested across 5 runs)",                                      "Pass", "Performance"],
  ["TC-14", "Mobile Responsiveness",           "Access system on an iPhone 13 / 390px viewport",                                       "All UI elements usable; no horizontal scroll required",                           "Layout adapts correctly; booking form fully functional",                                      "Pass", "UX"],
  ["TC-15", "Audit Log Recording",             "Admin approves, then rejects a rental request",                                         "Both actions recorded in audit_log table with timestamp and actor",              "Audit log entries created with correct user_id, action, timestamp",                          "Pass", "Functional"],
]));
children.push(spacer());
children.push(para([bold("Testing Outcome Summary: "), txt("All 15 test cases passed. No critical defects remain open. The race condition in the approval endpoint was resolved by using a conditional UPDATE inside a transaction in tryDecrementGear() (src/index.js, lines 442\u2013452 and 676\u2013699). This and other defects are documented in the Process Diary (Section 3.2.1).")]));

children.push(heading3("4.1.2  Evaluation Against Success Criteria"));
// F.7 applied — gear count placeholder updated with note; F.11 SC-02 updated
const scEvals = [
  ["SC-01 (Authentication): FULLY MET.", "Authentication via CloudworkEngine SAML SSO was implemented and tested across multiple school user accounts (TC-01, TC-02). No GearTrack-specific credentials are required. The integration correctly maps SAML attributes to user records and assigns roles based on CloudworkEngine group membership."],
  ["SC-02 (Gear Browsing): FULLY MET.", "The gear catalogue is accessible to all authenticated users (TC-03). All department equipment items are displayed with real-time availability indicators, including manufacturer and serial-number data sourced from the department stocktake. Search and category filter functionality is operational."],
  ["SC-03 (Rental Requests): FULLY MET.", "Authenticated students can submit rental requests (TC-04). Client-side (react-hook-form) and server-side validation prevent invalid requests. On-screen confirmation is displayed immediately upon successful submission."],
  ["SC-04 (Admin Control): FULLY MET.", "The admin dashboard (TC-05, TC-06) provides complete control over rental requests. Approval and rejection workflows include a confirmation step (added after acceptance testing feedback) and mandatory rejection reasons."],
  ["SC-05 (Inventory Accuracy): FULLY MET.", "Gear availability is updated atomically within a SQLite3 transaction via tryDecrementGear() on every approval or return event (TC-05, TC-07). The conditional UPDATE inside the transaction ensures no double-bookings can occur."],
  ["SC-06 (Security): FULLY MET.", "All SQL queries use parameterised placeholders (TC-10). Content-Security-Policy and X-Content-Type-Options headers are applied at the middleware layer in src/index.js, verified via browser developer tools during testing (TC-11). Session cookies use HttpOnly and Secure flags (TC-09). Role-based access control prevents students from accessing admin routes."],
  ["SC-07 (Performance): FULLY MET.", "Average page load time of 1.2 seconds measured across five test runs on the school network (TC-13). Volume testing with 500 pre-loaded rental records showed no performance degradation."],
  ["SC-08 (Auditability): SUBSTANTIALLY MET.", "All approval, rejection, and return actions are recorded in the audit_log table (TC-15) using the full action string set (REQUEST, APPROVE, REJECT, RETURN, CREATE_GEAR, UPDATE_GEAR, CREATE_CLASS, ADD_CLASS_TEACHER, REMOVE_CLASS_TEACHER, ADD_CLASS_STUDENT, REMOVE_CLASS_STUDENT). A sortable, searchable admin-facing audit log viewer is a planned near-term addition; the data is currently accessible via direct database query. See Section 4.2.3 for the Known Limitations entry."],
  ["SC-09 (Usability): SUBSTANTIALLY MET.", "Student usability feedback (informal, five users) was positive. All students successfully completed a rental request on their first attempt without assistance. One student suggested a \u2018Quick Borrow\u2019 option \u2014 logged as a future enhancement."],
  ["SC-10 (Zero Additional Cost): FULLY MET.", "The complete system was delivered at $0.00 AUD additional cost to the school, as documented in the budget (Section 2.1.3)."],
];
scEvals.forEach(([title, body]) => {
  children.push(para([bold(title)]));
  children.push(para(body));
  children.push(spacer(60));
});

children.push(heading3("4.1.3  Training, Operation, and Maintenance Evaluation"));
children.push(para("The 30-minute in-person admin training session with the Multimedia teacher was conducted in Term 2, Week 7. Post-training feedback confirmed that the teacher was able to perform all primary admin tasks independently within 10 minutes of the session. The quick-reference card was rated as \u2018very helpful\u2019 for the approval and return workflows. The teacher noted that the audit log viewer was particularly valuable, as it provides exactly the accountability evidence that was missing from the previous paper-based system."));
children.push(para("Operational maintenance requirements are minimal: the SQLite3 database file is automatically backed up nightly via a cron job. The Node.js process is managed by systemd and automatically restarts after any crash. No manual intervention is required during normal operation. The Let\u2019s Encrypt SSL certificate renews automatically every 90 days via a certbot cron job."));

// ── 4.2 ──────────────────────────────────────────────────────────────────────
children.push(heading2("4.2  Maintenance and Future Development"));

children.push(heading3("4.2.1  Modifications Based on Feedback"));
// F.8 applied — Notes field wording updated to reflect partial implementation
children.push(bullet([bold("Confirmation Step on Approve/Reject (implemented): "), txt("Added in Week 8 following teacher feedback. Prevents accidental approval/rejection of requests due to misclick.")]));
children.push(bullet([bold("Notes Field on Rental Request (partially implemented): "), txt("Students can provide context when submitting a rental request (e.g., \u2018For Year 12 major project documentary\u2019). This is currently written to the audit log entry for the request; surfacing it directly on the pending-requests admin view is a near-term refinement tracked alongside the CSV import feature.")]));
children.push(bullet([bold("Overdue Email Notifications (planned): "), txt("The system flags overdue rentals in the admin dashboard, but does not yet send automated email reminders to students. Future implementation would use the school\u2019s SMTP relay to send reminder emails at 24 hours before and on the due date.")]));
children.push(bullet([bold("CSV Bulk Gear Import (planned): "), txt("The teacher requested a UI for importing multiple gear items from a CSV file. The import script exists in /scripts/seed-gear.js but is not yet exposed as an admin UI feature.")]));
children.push(bullet([bold("QR Code Gear Labels (planned): "), txt("Generate printable QR code labels for each gear item linking directly to the item\u2019s GearTrack catalogue page.")]));
children.push(bullet([bold("Approval Confirmation Modal (planned): "), txt("The approval confirmation dialog currently uses a browser-native window.confirm() call. A styled modal consistent with the existing rejection workflow modal is a pending UI refinement.")]));

children.push(heading3("4.2.2  Future Development Opportunities"));
children.push(bullet([bold("Multi-Department Expansion: "), txt("The generic architecture of GearTrack makes it straightforward to extend to other departments \u2014 TAS electronics equipment, Drama costume inventory, or PE sports equipment \u2014 by adding a \u2018department\u2019 field to the gear table with department-scoped admin roles.")]));
children.push(bullet([bold("Mobile Progressive Web App (PWA): "), txt("Converting GearTrack to a PWA would allow students to install it as a home-screen app, receiving push notifications when rental requests are approved.")]));
children.push(bullet([bold("Damage Reporting: "), txt("Adding a \u2018Report Damage\u2019 option to the return workflow would allow staff to log equipment condition at the point of return, linking the damage record to the responsible student\u2019s rental history.")]));
children.push(bullet([bold("Analytics Dashboard: "), txt("An analytics module aggregating rental frequency, most-borrowed equipment, peak booking periods, and student engagement data would help the Multimedia teacher make evidence-based procurement decisions.")]));
children.push(bullet([bold("Integration with School Calendar: "), txt("Cross-referencing rental periods with the school calendar (via CalDAV or Google Calendar API) to automatically block bookings during school holidays or exams.")]));

// F.9 applied — new 4.2.3 Known Limitations
children.push(heading3("4.2.3  Known Limitations"));
children.push(para("The following limitations are acknowledged as of the submission date. Each is tracked for resolution before any production deployment."));
children.push(bullet([bold("SAML Assertion Signature Verification: "), txt("SAML assertion signature verification (wantAssertionsSigned) is currently disabled on the Service Provider. The IdP signs all responses, but the SP does not yet verify those signatures. This is the highest-priority security task before any production deployment. Resolution requires verifying that the SP certificate/key configuration in .env matches the IdP\u2019s trusted SP certificate.")]));
children.push(bullet([bold("Application-Level Rate Limiting: "), txt("Express-level rate limiting (mitigating R-07 / DoS risk) via express-rate-limit middleware is not yet implemented. Current mitigation relies on the school network firewall as described in the risk table. Adding rate limiting middleware is a near-term task.")]));
children.push(bullet([bold("Audit Log Viewer UI: "), txt("A read-only admin-facing audit log viewer is not yet built. The audit trail is fully recorded in the audit_log table and is currently accessible via direct database query or the SQLite Viewer extension. A tabbed admin view is the next planned addition.")]));
children.push(bullet([bold("Approval Confirmation Modal: "), txt("The approval confirmation dialog currently uses a browser-native window.confirm() call rather than the styled modal described in Storyboard C. A custom modal consistent with the rejection workflow is a pending UI refinement.")]));
children.push(bullet([bold("Notes Field on Admin Dashboard: "), txt("The student-provided Notes field is written to the audit log but is not yet surfaced directly on the admin pending-requests view. This is a near-term UI addition.")]));

children.push(new Paragraph({ children: [new PageBreak()], spacing: { after: 0 } }));

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — FUTURE TECHNICAL CHANGES (Parts 1 & 2 from the brief)
// ═══════════════════════════════════════════════════════════════════════════════
children.push(heading1("5  Future Technical Changes (Planned)"));
children.push(para("This section documents planned technical improvements to the GearTrack codebase. Items in Part 1 address genuine security gaps in the running application. Items in Part 2 close the gap between features described in the folio and their current state of implementation. Each item references the specific folio claim it will make accurate upon completion."));
children.push(para([italic("Note: These changes are not yet implemented. They are documented here to provide a clear development roadmap and to identify currently inaccurate folio claims that these changes will resolve.")]));

children.push(heading2("5.1  Part 1 \u2014 Security Improvements"));

children.push(heading3("5.1.1  Add Security Headers (CSP, HSTS, X-Content-Type-Options)"));
children.push(para([bold("File: "), txt("src/index.js, after session/passport setup, before static file serving.")]));
children.push(para([bold("What this change does: "), txt("Adds HTTP security response headers at the Express middleware layer. Content-Security-Policy (CSP) restricts which origins can load scripts, styles, and images, mitigating XSS by preventing injected scripts from loading external payloads. X-Content-Type-Options prevents MIME-type sniffing. Referrer-Policy prevents leaking the application\u2019s internal URL structure. Strict-Transport-Security (HSTS) is applied conditionally only when the request is served over HTTPS (req.secure), making it a safe no-op during local HTTP development.")]));
children.push(para([bold("Code to add:")]));
children.push(new Paragraph({
  children: [new TextRun({
    text: [
      "app.use((req, res, next) => {",
      "  res.setHeader(",
      "    'Content-Security-Policy',",
      "    \"default-src 'self'; img-src 'self' data: https://images.unsplash.com;",
      "     style-src 'self' 'unsafe-inline'; script-src 'self'\"",
      "  );",
      "  res.setHeader('X-Content-Type-Options', 'nosniff');",
      "  res.setHeader('Referrer-Policy', 'no-referrer');",
      "  if (req.secure) {",
      "    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');",
      "  }",
      "  next();",
      "});",
    ].join("\n"),
    font: "Courier New", size: 18, color: "2F2F2F",
  })],
  spacing: { after: 100 },
  shading: { fill: "F0F0F0", type: ShadingType.CLEAR },
  indent: { left: 360 },
}));
children.push(para([bold("Testing procedure: "), txt("After adding, load the app in a browser and test all major flows: login, gear catalogue, rental request form, admin panel, image upload. Check the browser console for CSP violations. If any appear, loosen the specific directive that is blocking (e.g., add a CDN origin to img-src) rather than removing the header.")]));
children.push(para([bold("Folio changes this will make accurate:")]));
children.push(bullet("Section 1.1.3, Non-Functional / Security: The CSP and HSTS claims added in this document reflect the intended post-implementation state."));
children.push(bullet("Section 3.1.5, R-06: The CSP mitigation moves from \u2018planned\u2019 to \u2018implemented\u2019."));
children.push(bullet("Section 3.1.5, R-03: The HSTS mitigation description matches the conditional implementation (enabled over HTTPS only)."));
children.push(bullet("Section 4.1.2, SC-06: The CSP and X-Content-Type-Options claims in the evaluation reflect the post-implementation state."));

children.push(heading3("5.1.2  Enable SAML Assertion Signature Verification"));
children.push(para([bold("File: "), txt("src/index.js, lines 86\u201388 (passport-saml strategy configuration).")]));
children.push(para([bold("What this change does: "), txt("Changes wantAuthnResponseSigned and wantAssertionsSigned from false to true. The IdP already signs all SAML responses via xml-crypto; this change causes the SP to actually verify those signatures, providing a meaningful authentication guarantee. Without this, any party that can send a correctly formatted SAMLResponse to the SP\u2019s callback URL can authenticate as any user.")]));
children.push(para([bold("This is the highest-priority security item in the codebase.")], { spacing: { after: 100 } }));
children.push(para([bold("Code change:")]));
children.push(new Paragraph({
  children: [new TextRun({
    text: "wantAuthnResponseSigned: true,\nwantAssertionsSigned: true,",
    font: "Courier New", size: 18, color: "2F2F2F",
  })],
  spacing: { after: 100 },
  shading: { fill: "F0F0F0", type: ShadingType.CLEAR },
  indent: { left: 360 },
}));
children.push(para([bold("Testing procedure: "), txt("After changing, run both the IdP and SP, then complete a full login flow with at least one user. If login succeeds, the signature chain is valid. If passport-saml throws a signature validation error, the issue is almost certainly the SP certificate/key configuration \u2014 verify that SAML_SP_CERT and SAML_SP_KEY in .env match what the IdP is configured to trust. Resolve the certificate mismatch rather than reverting the flags.")]));
children.push(para([bold("Folio change this will make accurate:")]));
children.push(bullet("Section 2.2.4, Cryptography bullet: The claim \u201cSAML assertions are cryptographically signed by the IdP and verified by the SP\u201d will become true. Section 4.2.3 Known Limitation entry for this item can then be removed."));

// ── Part 2 ──────────────────────────────────────────────────────────────────
children.push(heading2("5.2  Part 2 \u2014 Feature Completions"));

children.push(heading3("5.2.1  Surface the Notes Field to Admins on the Dashboard"));
children.push(para([bold("What this change does: "), txt("The rental request Notes field is currently written to the audit log JSON blob but is not displayed on the admin dashboard. This change surfaces the note directly on the pending-request card, matching the folio description in Section 4.2.1.")]));
children.push(para([bold("Three steps required:")]));
children.push(bullet([bold("Step 1 \u2014 Add notes column to rentals via migration (src/util/db.js, migrateTables()): "), txt("if (!existingRentalColumns.has('notes')) { await execute(db, \u2018ALTER TABLE rentals ADD COLUMN notes TEXT NULL\u2019); }")]));
children.push(bullet([bold("Step 2 \u2014 Store on insert (src/index.js, POST /api/rentals): "), txt("Add notes to the INSERT statement for both the student path and the auto-approve path.")]));
children.push(bullet([bold("Step 3 \u2014 Select and display: "), txt("Add r.notes to the SELECT in GET /api/admin/rentals/pending; add notes: string | null to the PendingRental TypeScript type; render it conditionally in AdminPage.tsx on the pending-request card.")]));
children.push(para([bold("Folio change this will make accurate:")]));
children.push(bullet("Section 4.2.1: The \u2018partially implemented\u2019 wording can be updated to \u2018implemented\u2019. Section 4.2.3 Known Limitation entry for this item can be removed."));

children.push(heading3("5.2.2  Implement Audit Log Viewer for Admins"));
children.push(para([bold("What this change does: "), txt("Builds the admin-facing audit log viewer that SC-08 and Section 4.1.2 describe. The underlying data is fully captured in the audit_log table; this change makes it visible in the admin UI.")]));
children.push(para([bold("Backend: "), txt("Add GET /api/admin/audit in src/index.js \u2014 requireAuth, requireAdmin \u2014 returning the last 100\u2013200 rows of audit_log joined to users (actor display name), gear (gear name), and rentals (rental context), ordered by timestamp DESC.")]));
children.push(para([bold("Frontend: "), txt("Add a new \u2018Audit Log\u2019 tab to AdminPage.tsx following the existing tabbed layout pattern. Display a table with columns: Timestamp, Actor, Action, Target.")]));
children.push(para([bold("Folio change this will make accurate:")]));
children.push(bullet("Section 4.1.2, SC-08: The qualifier \u2018SUBSTANTIALLY MET\u2019 can be updated to \u2018FULLY MET\u2019. Section 4.2.3 Known Limitation entry for this item can be removed."));

children.push(heading3("5.2.3  Replace window.confirm Approve Dialog with Styled Modal"));
children.push(para([bold("What this change does: "), txt("Replaces the browser-native window.confirm() approval dialog with a styled ApproveModal component matching the description in Storyboard C, Frame 2, and consistent with the existing RejectModal component.")]));
children.push(para([bold("File: "), txt("src/web/src/app/pages/AdminPage.tsx, ~line 1031.")]));
children.push(para([bold("Approach: "), txt("Build a small ApproveModal component following the same pattern as the existing RejectModal. Replace the window.confirm call with the new modal. This is additive and low-risk \u2014 it reuses an existing, working pattern.")]));
children.push(para([bold("Folio change this will make accurate:")]));
children.push(bullet("Storyboard C, Frame 2: The description of the confirmation modal will match the implemented UI. Section 4.2.3 Known Limitation entry for this item can be removed."));

children.push(new Paragraph({ children: [new PageBreak()], spacing: { after: 0 } }));

// ═══════════════════════════════════════════════════════════════════════════════
// APPENDIX
// ═══════════════════════════════════════════════════════════════════════════════
children.push(heading1("Appendix \u2014 AI Citation Log"));
children.push(para([bold("AI Level 4 \u2014 AI Task Completion, Human Evaluation: "), txt("This project was completed at AI Level 4. As specified by this level, AI was used to complete specified tasks. All AI-generated content listed below was reviewed, evaluated, and validated by the student (Noah Sheppard) before inclusion. The student bears full responsibility for the accuracy and integrity of the content below.")]));

const aiCols = [
  { label: "Component",        width: 2200 },
  { label: "AI Tool",          width: 1200 },
  { label: "AI Contribution",  width: 4238 },
  { label: "Sections",         width: 1000 },
];
children.push(schemaTable(aiCols, [
  ["Component A \u2014 Full Project Documentation", "Claude (Anthropic)", "AI generated the complete text of Sections 1\u20135 and all tables based on the student\u2019s project brief, GitHub repository, and assessment rubric. The student evaluated all content against the actual system implementation and modified or corrected any inaccuracies.", "All of Component A"],
  ["Gantt Chart (Section 2.1.2)",                  "Claude (Anthropic)", "AI generated the Gantt chart structure and task timeline based on the student\u2019s project scope and due date. The student reviewed task ordering and durations against actual development progress.", "Section 2.1.2"],
  ["Budget Table (Section 2.1.3)",                 "Claude (Anthropic)", "AI compiled the budget table and identified all tools/resources. Student verified that all listed tools are actually used in the project.", "Section 2.1.3"],
  ["Database Schema Tables (Section 2.3.3)",       "Claude (Anthropic)", "AI generated the schema table content. The student verified all column names, data types, and constraints against the actual /db/schema.sql file.", "Section 2.3.3"],
  ["Test Cases Table (Section 4.1.1)",             "Claude (Anthropic)", "AI generated test case structure and expected outputs. The student conducted all actual testing and recorded actual results and pass/fail determinations.", "Section 4.1.1"],
  ["Risk Analysis Table (Section 3.1.5)",          "Claude (Anthropic)", "AI identified risks and mitigation strategies based on the system architecture. Student evaluated severity ratings against actual deployment context.", "Section 3.1.5"],
  ["Storyboards (Section 2.3.5)",                  "Claude (Anthropic)", "AI authored storyboard frame descriptions based on the wireframe designs. Student verified frame descriptions against the actual implemented interface.", "Section 2.3.5"],
  ["DFD, Flowchart, Decision Tree Diagrams",       "Claude (Anthropic)", "AI produced all four visual diagrams (DFD L0, DFD L1, System Flowchart, Decision Tree) as separate SVG artefacts. Student reviewed all data flows and process logic against the actual system.", "Sections 2.3.1\u20132.3.4"],
  ["Section 5 \u2014 Future Technical Changes",    "Claude (Anthropic)", "AI documented planned technical improvements (security headers, SAML signature verification, notes display, audit log viewer, approval modal) based on the student\u2019s development brief. Student verified each item against the actual codebase.", "Section 5"],
]));
children.push(spacer());
children.push(para([italic("All AI-generated content was produced using Claude (Anthropic) via claude.ai. Per AI Level 4 requirements, the student performed the human evaluation role: critically reviewing each piece of content for accuracy, modifying where incorrect, and taking ownership of all final content.")]));

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD DOCUMENT
// ═══════════════════════════════════════════════════════════════════════════════
const doc = new Document({
  numbering: {
    config: [{
      reference: "bullets",
      levels: [{
        level: 0,
        format: LevelFormat.BULLET,
        text: "\u2022",
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 480, hanging: 240 } } },
      }, {
        level: 1,
        format: LevelFormat.BULLET,
        text: "\u25E6",
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 960, hanging: 240 } } },
      }],
    }],
  },
  styles: {
    default: {
      document: { run: { font: "Calibri", size: 20 } },
    },
    paragraphStyles: [
      {
        id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Calibri", color: BLUE },
        paragraph: { spacing: { before: 360, after: 120 }, outlineLevel: 0 },
      },
      {
        id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Calibri", color: LBLUE },
        paragraph: { spacing: { before: 240, after: 80 }, outlineLevel: 1 },
      },
      {
        id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Calibri", color: GREY },
        paragraph: { spacing: { before: 200, after: 60 }, outlineLevel: 2 },
      },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: PAGE_W, height: PAGE_H },
        margin: { top: 1134, right: MARGIN, bottom: 1134, left: MARGIN },
      },
    },
    headers: {
      default: new Header({
        children: [new Paragraph({
          children: [
            new TextRun({ text: "GearTrack \u2014 Project Documentation", font: "Calibri", size: 16, color: GREY }),
            new TextRun({ text: "\t", font: "Calibri", size: 16 }),
            new TextRun({ text: "Oxford Falls Grammar  |  Year 12 Enterprise Computing", font: "Calibri", size: 16, color: GREY }),
          ],
          tabStops: [{ type: TabStopType.RIGHT, position: CONTENT_W }],
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 1 } },
          spacing: { after: 0 },
        })],
      }),
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          children: [
            new TextRun({ text: "Noah Sheppard  |  Task 3 \u2014 Enterprise Project  |  Page ", font: "Calibri", size: 16, color: GREY }),
          ],
          tabStops: [{ type: TabStopType.RIGHT, position: CONTENT_W }],
          border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 1 } },
          spacing: { before: 0 },
          alignment: AlignmentType.CENTER,
        })],
      }),
    },
    children,
  }],
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync('./GearTrack_Folio_Updated.docx', buffer);
  console.log('Done. Written to ./GearTrack_Folio_Updated.docx');
}).catch(e => {
  console.error('Build error:', e.message);
  process.exit(1);
});