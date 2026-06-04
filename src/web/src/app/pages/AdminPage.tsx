import { useState, useEffect, useRef } from "react";
import { MOCK_CLASSES, MOCK_STUDENTS, MOCK_GEAR, MOCK_GEAR_UNITS, MOCK_RENTALS } from "../data";
import { Search, X, Package, Users, BookOpen, AlertTriangle, ChevronRight, Clock } from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────────

type ModalPayload =
  | { type: "gear"; id: string }
  | { type: "student"; id: string }
  | { type: "class"; id: string }
  | null;

// ─── Modal shell ─────────────────────────────────────────────────────────────

function Modal({ onClose, children }: { onClose: () => void; children: React.ReactNode }) {
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handleKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handleKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.35)" }}
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
    >
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg max-h-[85vh] flex flex-col overflow-hidden">
        {children}
      </div>
    </div>
  );
}

// ─── Dot indicator ───────────────────────────────────────────────────────────

function StatusDot({ status }: { status: "available" | "out" | "overdue" }) {
  const colors = { available: "bg-emerald-500", out: "bg-amber-400", overdue: "bg-red-500" };
  return <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${colors[status]}`} />;
}

// ─── Gear detail modal ────────────────────────────────────────────────────────

function GearModal({ id, onClose }: { id: string; onClose: () => void }) {
  const gear = MOCK_GEAR.find((g) => g.id === id)!;
  const units = MOCK_GEAR_UNITS.filter((u) => u.gearId === id);
  const rentedCount = MOCK_RENTALS.filter((r) => r.gearId === id).length;
  const overdueCount = MOCK_RENTALS.filter((r) => r.gearId === id && r.status === "Overdue").length;

  return (
    <Modal onClose={onClose}>
      {/* Header */}
      <div className="flex items-start gap-4 p-5 border-b border-gray-100">
        <img src={gear.photo} alt={gear.name} className="w-16 h-16 rounded-xl object-cover shrink-0 bg-gray-100" />
        <div className="flex-1 min-w-0">
          <h2 className="text-gray-900 pr-6">{gear.name}</h2>
          <p className="text-sm text-gray-400 mt-0.5">{gear.category} · max {gear.maxRentDays} days</p>
          <div className="flex items-center gap-3 mt-2 text-sm">
            <span className="text-gray-500">
              <span className="font-semibold text-gray-800">{gear.stock - rentedCount}</span> of {gear.stock} available
            </span>
            {overdueCount > 0 && (
              <span className="text-red-600 flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                {overdueCount} overdue
              </span>
            )}
          </div>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors mt-0.5">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Unit list */}
      <div className="overflow-y-auto flex-1">
        <div className="px-5 py-2 bg-gray-50 border-b border-gray-100">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Unit Status</p>
        </div>
        <ul className="divide-y divide-gray-100">
          {units.map((unit) => {
            const rental = MOCK_RENTALS.find((r) => r.unitId === unit.id);
            const student = rental ? MOCK_STUDENTS.find((s) => s.id === rental.studentId) : null;
            const isOverdue = rental?.status === "Overdue";
            const status = isOverdue ? "overdue" : rental ? "out" : "available";

            return (
              <li key={unit.id} className="flex items-center gap-3 px-5 py-3.5">
                <StatusDot status={status} />
                <span className="text-sm font-medium text-gray-700 w-24 shrink-0">{unit.label}</span>
                <div className="flex-1 text-sm">
                  {student ? (
                    <span className="text-gray-800">{student.name}</span>
                  ) : (
                    <span className="text-gray-400">Available</span>
                  )}
                </div>
                {rental && (
                  <div className="text-right shrink-0">
                    <span className={`text-xs ${isOverdue ? "text-red-600 font-medium" : "text-gray-400"}`}>
                      {isOverdue ? "Overdue · " : "Due "}
                      {new Date(rental.dueDate).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                    </span>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </Modal>
  );
}

// ─── Student detail modal ─────────────────────────────────────────────────────

function StudentModal({ id, onClose }: { id: string; onClose: () => void }) {
  const student = MOCK_STUDENTS.find((s) => s.id === id)!;
  const rentals = MOCK_RENTALS.filter((r) => r.studentId === id);
  const classes = MOCK_CLASSES.filter((c) => c.students.includes(id));
  const overdueCount = rentals.filter((r) => r.status === "Overdue").length;
  const initials = student.name.split(" ").map((n) => n[0]).join("");

  return (
    <Modal onClose={onClose}>
      <div className="flex items-center gap-4 p-5 border-b border-gray-100">
        <div className="w-12 h-12 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold shrink-0">
          {initials}
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="text-gray-900">{student.name}</h2>
          <p className="text-sm text-gray-400">{student.email}</p>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="overflow-y-auto flex-1 divide-y divide-gray-100">
        {/* Classes */}
        <div>
          <div className="px-5 py-2 bg-gray-50 border-b border-gray-100">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
              <BookOpen className="w-3.5 h-3.5" /> Classes · {classes.length} enrolled
            </p>
          </div>
          {classes.length > 0 ? (
            <ul className="divide-y divide-gray-100">
              {classes.map((c) => (
                <li key={c.id} className="px-5 py-3 text-sm text-gray-700">{c.name}</li>
              ))}
            </ul>
          ) : (
            <p className="px-5 py-4 text-sm text-gray-400">Not enrolled in any classes.</p>
          )}
        </div>

        {/* Rentals */}
        <div>
          <div className="px-5 py-2 bg-gray-50 border-b border-gray-100">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" /> Rentals · {rentals.length} active
              {overdueCount > 0 && <span className="text-red-500 ml-1">({overdueCount} overdue)</span>}
            </p>
          </div>
          {rentals.length > 0 ? (
            <ul className="divide-y divide-gray-100">
              {rentals.map((rental) => {
                const gear = MOCK_GEAR.find((g) => g.id === rental.gearId);
                const unit = MOCK_GEAR_UNITS.find((u) => u.id === rental.unitId);
                const isOverdue = rental.status === "Overdue";
                return (
                  <li key={rental.id} className="flex items-center gap-3 px-5 py-3.5">
                    <StatusDot status={isOverdue ? "overdue" : "out"} />
                    {gear && (
                      <img src={gear.photo} alt={gear.name} className="w-9 h-9 rounded-lg object-cover shrink-0 bg-gray-100" />
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-800 truncate">{gear?.name ?? "Unknown"}</p>
                      <p className="text-xs text-gray-400">{unit?.label}</p>
                    </div>
                    <div className="text-right shrink-0 text-xs">
                      <p className={isOverdue ? "text-red-600 font-medium" : "text-gray-500"}>
                        {isOverdue ? "Overdue" : "Due"} {new Date(rental.dueDate).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                      </p>
                    </div>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="px-5 py-4 text-sm text-gray-400">No active rentals.</p>
          )}
        </div>
      </div>
    </Modal>
  );
}

// ─── Class detail modal ───────────────────────────────────────────────────────

function ClassModal({ id, onClose }: { id: string; onClose: () => void }) {
  const cls = MOCK_CLASSES.find((c) => c.id === id)!;

  return (
    <Modal onClose={onClose}>
      <div className="flex items-center gap-4 p-5 border-b border-gray-100">
        <div className="w-10 h-10 rounded-xl bg-blue-50 flex items-center justify-center shrink-0">
          <BookOpen className="w-5 h-5 text-blue-600" />
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="text-gray-900">{cls.name}</h2>
          <p className="text-sm text-gray-400">{cls.students.length} students enrolled</p>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="overflow-y-auto flex-1">
        <div className="px-5 py-2 bg-gray-50 border-b border-gray-100">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Enrolled Students</p>
        </div>
        <ul className="divide-y divide-gray-100">
          {cls.students.map((sId) => {
            const student = MOCK_STUDENTS.find((s) => s.id === sId);
            if (!student) return null;
            const rentals = MOCK_RENTALS.filter((r) => r.studentId === sId);
            const overdue = rentals.filter((r) => r.status === "Overdue").length;
            const initials = student.name.split(" ").map((n) => n[0]).join("");

            return (
              <li key={sId} className="flex items-center gap-3 px-5 py-3.5">
                <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold shrink-0">
                  {initials}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-800">{student.name}</p>
                  <p className="text-xs text-gray-400">{student.email}</p>
                </div>
                <div className="text-right text-xs shrink-0">
                  {rentals.length > 0 ? (
                    <p className={overdue > 0 ? "text-red-600 font-medium" : "text-gray-500"}>
                      {rentals.length} rental{rentals.length !== 1 ? "s" : ""}
                      {overdue > 0 && ` · ${overdue} overdue`}
                    </p>
                  ) : (
                    <p className="text-gray-400">No rentals</p>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </Modal>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

const TABS = [
  { id: "gear" as const, label: "Inventory", icon: Package },
  { id: "students" as const, label: "Students", icon: Users },
  { id: "classes" as const, label: "Classes", icon: BookOpen },
];

export function AdminPage() {
  const [activeTab, setActiveTab] = useState<"gear" | "students" | "classes">("gear");
  const [search, setSearch] = useState("");
  const [modal, setModal] = useState<ModalPayload>(null);

  const overdueRentals = MOCK_RENTALS.filter((r) => r.status === "Overdue").length;
  const rentedUnits = MOCK_GEAR_UNITS.filter((u) => MOCK_RENTALS.some((r) => r.unitId === u.id)).length;

  return (
    <div className="space-y-6">
      {modal?.type === "gear" && <GearModal id={modal.id} onClose={() => setModal(null)} />}
      {modal?.type === "student" && <StudentModal id={modal.id} onClose={() => setModal(null)} />}
      {modal?.type === "class" && <ClassModal id={modal.id} onClose={() => setModal(null)} />}

      {/* Page header */}
      <div>
        <h1 className="text-gray-900">Admin Dashboard</h1>
        <p className="text-gray-500 text-sm mt-0.5">Multimedia Department · Equipment &amp; Enrollment</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Total Units", value: MOCK_GEAR_UNITS.length },
          { label: "Out on Loan", value: rentedUnits },
          { label: "Overdue", value: overdueRentals, warn: overdueRentals > 0 },
          { label: "Students", value: MOCK_STUDENTS.length },
        ].map((s) => (
          <div
            key={s.label}
            className={`rounded-xl border px-4 py-3 bg-white ${s.warn ? "border-red-200" : "border-gray-200"}`}
          >
            <div className={`text-2xl font-bold ${s.warn ? "text-red-600" : "text-gray-900"}`}>{s.value}</div>
            <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs + search */}
      <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
        <div className="flex border border-gray-200 rounded-lg overflow-hidden bg-white">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => { setActiveTab(id); setSearch(""); }}
              className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium transition-colors border-r last:border-r-0 border-gray-200 ${
                activeTab === id ? "bg-gray-900 text-white" : "text-gray-600 hover:bg-gray-50"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </button>
          ))}
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            className="pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 w-48"
            placeholder={`Search ${activeTab}…`}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
        {activeTab === "gear" && (
          <table className="min-w-full">
            <thead className="border-b border-gray-100 bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Item</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Availability</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {MOCK_GEAR.filter((g) => g.name.toLowerCase().includes(search.toLowerCase())).map((gear) => {
                const rentals = MOCK_RENTALS.filter((r) => r.gearId === gear.id);
                const overdue = rentals.filter((r) => r.status === "Overdue").length;
                const available = gear.stock - rentals.length;

                return (
                  <tr
                    key={gear.id}
                    className="hover:bg-gray-50 cursor-pointer transition-colors"
                    onClick={() => setModal({ type: "gear", id: gear.id })}
                  >
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-3">
                        <img src={gear.photo} alt={gear.name} className="w-10 h-10 rounded-lg object-cover shrink-0 bg-gray-100" />
                        <div>
                          <p className="font-medium text-gray-900 text-sm">{gear.name}</p>
                          <p className="text-xs text-gray-400">{gear.category}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-1.5">
                        {MOCK_GEAR_UNITS.filter((u) => u.gearId === gear.id).map((unit) => {
                          const r = MOCK_RENTALS.find((r) => r.unitId === unit.id);
                          return (
                            <span
                              key={unit.id}
                              title={unit.label}
                              className={`w-2.5 h-2.5 rounded-full ${
                                r?.status === "Overdue" ? "bg-red-500" : r ? "bg-amber-400" : "bg-emerald-500"
                              }`}
                            />
                          );
                        })}
                      </div>
                      <p className="text-xs text-gray-400 mt-1.5">{available} of {gear.stock} free</p>
                    </td>
                    <td className="px-5 py-4">
                      {overdue > 0 ? (
                        <span className="inline-flex items-center gap-1 text-xs text-red-600">
                          <AlertTriangle className="w-3.5 h-3.5" /> {overdue} overdue
                        </span>
                      ) : rentals.length === 0 ? (
                        <span className="text-xs text-gray-400">All in</span>
                      ) : (
                        <span className="text-xs text-gray-500">{rentals.length} out</span>
                      )}
                    </td>
                    <td className="px-5 py-4 text-right">
                      <ChevronRight className="w-4 h-4 text-gray-300 inline" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {activeTab === "students" && (
          <table className="min-w-full">
            <thead className="border-b border-gray-100 bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Student</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Classes</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Rentals</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {MOCK_STUDENTS.filter((s) => s.name.toLowerCase().includes(search.toLowerCase())).map((student) => {
                const classes = MOCK_CLASSES.filter((c) => c.students.includes(student.id));
                const rentals = MOCK_RENTALS.filter((r) => r.studentId === student.id);
                const overdue = rentals.filter((r) => r.status === "Overdue").length;
                const initials = student.name.split(" ").map((n) => n[0]).join("");

                return (
                  <tr
                    key={student.id}
                    className="hover:bg-gray-50 cursor-pointer transition-colors"
                    onClick={() => setModal({ type: "student", id: student.id })}
                  >
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold shrink-0">
                          {initials}
                        </div>
                        <div>
                          <p className="font-medium text-gray-900 text-sm">{student.name}</p>
                          <p className="text-xs text-gray-400">{student.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-4 text-sm text-gray-500">{classes.length} class{classes.length !== 1 ? "es" : ""}</td>
                    <td className="px-5 py-4 text-sm">
                      <span className="text-gray-500">{rentals.length} active</span>
                      {overdue > 0 && <span className="ml-2 text-red-500 text-xs">{overdue} overdue</span>}
                    </td>
                    <td className="px-5 py-4 text-right">
                      <ChevronRight className="w-4 h-4 text-gray-300 inline" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {activeTab === "classes" && (
          <table className="min-w-full">
            <thead className="border-b border-gray-100 bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Class</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Students</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Active Rentals</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {MOCK_CLASSES.filter((c) => c.name.toLowerCase().includes(search.toLowerCase())).map((cls) => {
                const studentRentals = cls.students.flatMap((sId) =>
                  MOCK_RENTALS.filter((r) => r.studentId === sId)
                );
                const overdue = studentRentals.filter((r) => r.status === "Overdue").length;

                return (
                  <tr
                    key={cls.id}
                    className="hover:bg-gray-50 cursor-pointer transition-colors"
                    onClick={() => setModal({ type: "class", id: cls.id })}
                  >
                    <td className="px-5 py-4">
                      <p className="font-medium text-gray-900 text-sm">{cls.name}</p>
                    </td>
                    <td className="px-5 py-4 text-sm text-gray-500">{cls.students.length} enrolled</td>
                    <td className="px-5 py-4 text-sm">
                      <span className="text-gray-500">{studentRentals.length} total</span>
                      {overdue > 0 && <span className="ml-2 text-red-500 text-xs">{overdue} overdue</span>}
                    </td>
                    <td className="px-5 py-4 text-right">
                      <ChevronRight className="w-4 h-4 text-gray-300 inline" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
