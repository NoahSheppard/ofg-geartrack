import { useEffect, useState } from "react";
import { useCurrentUser } from "../hooks/useCurrentUser";
import { Mail, Clock, AlertCircle, CheckCircle, XCircle, Package, ListChecks } from "lucide-react";
import type { Rental, RentalStatus } from "../types";

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

export function ProfilePage() {
  const userState = useCurrentUser();
  const [rentals, setRentals] = useState<Rental[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/rentals/me", { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setRentals)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (userState.status === 'loading' || loading) {
    return <div className="text-gray-400 text-sm py-16 text-center">Loading…</div>;
  }
  if (userState.status === 'error') {
    return <div className="text-red-500 text-sm py-16 text-center">Could not load profile: {userState.message}</div>;
  }
  if (userState.status === 'unauthenticated') {
    return null;
  }
  if (error) {
    return <div className="text-red-500 text-sm py-16 text-center">Could not load rentals: {error}</div>;
  }

  const user = userState.user;
  const initials = [user.givenName, user.surname].filter(Boolean).map((n) => n![0]).join('') ||
    user.displayName.split(' ').map((n) => n[0]).join('').slice(0, 2);

  const pendingCount = rentals.filter((r) => r.status === "pending").length;
  const overdueCount = rentals.filter((r) => r.status === "overdue").length;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Profile card */}
      <div className="bg-white border border-gray-200 rounded-2xl p-6 flex items-center gap-5">
        <div className="w-16 h-16 rounded-full bg-blue-600 flex items-center justify-center text-white text-xl font-bold shrink-0">
          {initials}
        </div>
        <div className="flex-1 min-w-0">
          <h1 className="text-gray-900">{user.displayName}</h1>
          <div className="flex items-center gap-1.5 text-sm text-gray-500 mt-1">
            <Mail className="w-3.5 h-3.5" />
            {user.email}
          </div>
          {user.role && (
            <span className="inline-block mt-1.5 text-xs font-medium px-2 py-0.5 bg-blue-50 text-blue-600 rounded-full capitalize">
              {user.role}
            </span>
          )}
        </div>
        <div className="flex gap-6 text-center shrink-0">
          <div>
            <div className="text-xl font-bold text-gray-900">{rentals.length}</div>
            <div className="text-xs text-gray-400 mt-0.5">Total Requests</div>
          </div>
          <div>
            <div className="text-xl font-bold text-gray-900">{pendingCount}</div>
            <div className="text-xs text-gray-400 mt-0.5">Pending</div>
          </div>
          <div>
            <div className={`text-xl font-bold ${overdueCount > 0 ? "text-red-600" : "text-gray-900"}`}>
              {overdueCount}
            </div>
            <div className="text-xs text-gray-400 mt-0.5">Overdue</div>
          </div>
        </div>
      </div>

      {overdueCount > 0 && (
        <div className="flex items-start gap-3 px-4 py-3 bg-red-50 border border-red-200 rounded-xl text-sm text-red-700">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-red-500" />
          <span>
            You have <strong>{overdueCount} overdue item{overdueCount !== 1 ? "s" : ""}</strong>. Please return them as soon as possible.
          </span>
        </div>
      )}

      <section>
        <div className="flex items-center gap-2 mb-3">
          <ListChecks className="w-4 h-4 text-gray-400" />
          <h2 className="text-gray-800">Rental History</h2>
        </div>
        <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
          {rentals.length > 0 ? (
            <ul className="divide-y divide-gray-100">
              {rentals.map((rental) => {
                const status = STATUS_STYLES[rental.status];
                const Icon = status.icon;
                return (
                  <li key={rental.id} className="flex items-center gap-4 px-5 py-4 hover:bg-gray-50 transition-colors">
                    {rental.gearImage ? (
                      <img
                        src={rental.gearImage}
                        alt={rental.gearName}
                        className="w-12 h-12 rounded-lg object-cover shrink-0 bg-gray-100"
                      />
                    ) : (
                      <div className="w-12 h-12 rounded-lg shrink-0 bg-gray-100 flex items-center justify-center">
                        <Package className="w-5 h-5 text-gray-300" />
                      </div>
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-gray-900 truncate">{rental.gearName}</p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        Qty {rental.quantity} · {formatDate(rental.rentalStart)} – {formatDate(rental.returnDue)}
                      </p>
                      {rental.status === "rejected" && rental.rejectionReason && (
                        <p className="text-xs text-red-500 mt-1">Reason: {rental.rejectionReason}</p>
                      )}
                    </div>
                    <span
                      className={`flex items-center gap-1 text-xs font-medium px-2.5 py-1 rounded-full shrink-0 border ${status.className}`}
                    >
                      <Icon className="w-3 h-3" />
                      {status.label}
                    </span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="px-5 py-8 text-center text-gray-400 text-sm">No rental requests yet.</div>
          )}
        </div>
      </section>
    </div>
  );
}
