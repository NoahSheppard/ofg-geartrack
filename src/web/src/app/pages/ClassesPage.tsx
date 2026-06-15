import { useEffect, useState } from "react";
import { ChevronDown, ChevronUp, Users, GraduationCap, Package, Clock, CheckCircle, XCircle, AlertCircle } from "lucide-react";
import type { ClassSummary, MyClassDetail, RentalStatus } from "../types";

const STATUS_STYLES: Record<RentalStatus, { label: string; className: string; icon: typeof Clock }> = {
  pending:  { label: "Pending",  className: "bg-yellow-50 text-yellow-700 border-yellow-200", icon: Clock },
  approved: { label: "Approved", className: "bg-green-50 text-green-700 border-green-200",    icon: CheckCircle },
  rejected: { label: "Rejected", className: "bg-red-50 text-red-600 border-red-200",          icon: XCircle },
  returned: { label: "Returned", className: "bg-gray-50 text-gray-500 border-gray-200",       icon: Package },
  overdue:  { label: "Overdue",  className: "bg-red-50 text-red-600 border-red-200",          icon: AlertCircle },
};

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function ClassesPage() {
  const [classes, setClasses] = useState<ClassSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [details, setDetails] = useState<Record<number, MyClassDetail>>({});
  const [detailLoadingId, setDetailLoadingId] = useState<number | null>(null);

  useEffect(() => {
    fetch("/api/classes/me", { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setClasses)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (id: number) => {
    if (expandedId === id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(id);
    if (details[id]) return;

    setDetailLoadingId(id);
    fetch(`/api/classes/${id}`, { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((detail: MyClassDetail) => setDetails((prev) => ({ ...prev, [id]: detail })))
      .catch(() => {})
      .finally(() => setDetailLoadingId(null));
  };

  if (loading) {
    return <div className="text-gray-400 text-sm py-16 text-center">Loading…</div>;
  }
  if (error) {
    return <div className="text-red-500 text-sm py-16 text-center">Could not load classes: {error}</div>;
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-gray-900">My Classes</h1>
        <p className="text-gray-500 text-sm mt-0.5">Classes you're enrolled in, your teachers, classmates, and gear rented for each.</p>
      </div>

      <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden divide-y divide-gray-100">
        {classes.map((c) => {
          const isExpanded = expandedId === c.id;
          const detail = details[c.id];
          return (
            <div key={c.id}>
              <button
                onClick={() => toggle(c.id)}
                className="w-full flex items-center justify-between gap-3 px-5 py-4 text-left hover:bg-gray-50 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Users className="w-4 h-4 text-gray-400" />
                  <span className="font-medium text-gray-900 text-sm">{c.name}</span>
                </div>
                {isExpanded ? (
                  <ChevronUp className="w-4 h-4 text-gray-400" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-gray-400" />
                )}
              </button>

              {isExpanded && (
                <div className="px-5 pb-5 space-y-5">
                  {detailLoadingId === c.id || !detail ? (
                    <p className="text-sm text-gray-400">Loading…</p>
                  ) : (
                    <>
                      {detail.description && (
                        <p className="text-sm text-gray-500">{detail.description}</p>
                      )}

                      <section>
                        <h3 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-1.5">
                          <GraduationCap className="w-3.5 h-3.5 text-gray-400" /> Teachers
                        </h3>
                        <div className="space-y-1">
                          {detail.teachers.map((t) => (
                            <div key={t.id} className="px-3 py-1.5 bg-gray-50 rounded-lg">
                              <p className="text-sm text-gray-900">{t.displayName}</p>
                              <p className="text-xs text-gray-400">{t.email}</p>
                            </div>
                          ))}
                          {detail.teachers.length === 0 && <p className="text-xs text-gray-400">No teachers assigned.</p>}
                        </div>
                      </section>

                      <section>
                        <h3 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-1.5">
                          <Users className="w-3.5 h-3.5 text-gray-400" /> Classmates
                        </h3>
                        <div className="space-y-1">
                          {detail.students.map((s) => (
                            <div key={s.id} className="px-3 py-1.5 bg-gray-50 rounded-lg">
                              <p className="text-sm text-gray-900">{s.displayName}</p>
                              <p className="text-xs text-gray-400">{s.email}</p>
                            </div>
                          ))}
                          {detail.students.length === 0 && <p className="text-xs text-gray-400">No classmates yet.</p>}
                        </div>
                      </section>

                      <section>
                        <h3 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-1.5">
                          <Package className="w-3.5 h-3.5 text-gray-400" /> My Gear for This Class
                        </h3>
                        <div className="space-y-1">
                          {detail.myRentals.map((r) => {
                            const status = STATUS_STYLES[r.status];
                            const Icon = status.icon;
                            return (
                              <div key={r.id} className="flex items-center justify-between px-3 py-1.5 bg-gray-50 rounded-lg">
                                <span className="text-sm text-gray-800">{r.quantity} × {r.gearName}</span>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs text-gray-400">
                                    {formatDate(r.rentalStart)} – {formatDate(r.returnDue)}
                                  </span>
                                  <span className={`flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full border ${status.className}`}>
                                    <Icon className="w-3 h-3" />
                                    {status.label}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                          {detail.myRentals.length === 0 && <p className="text-xs text-gray-400">No gear rented for this class yet.</p>}
                        </div>
                      </section>
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {classes.length === 0 && (
          <div className="px-5 py-12 text-center text-gray-400 text-sm">You're not enrolled in any classes yet.</div>
        )}
      </div>
    </div>
  );
}
