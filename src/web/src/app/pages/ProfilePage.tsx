import { MOCK_RENTALS, MOCK_GEAR, MOCK_CLASSES } from "../data";
import { useCurrentUser } from "../hooks/useCurrentUser";
import { Mail, BookOpen, Clock, AlertCircle, CheckCircle } from "lucide-react";

// In production these would come from /api/rentals/me and /api/classes/me.
// For now we match on email against the mock data's hardcoded student "s1"
// so the page still works during development.
const DEV_STUDENT_ID = "s1";

export function ProfilePage() {
  const userState = useCurrentUser();

  if (userState.status === 'loading') {
    return <div className="text-gray-400 text-sm py-16 text-center">Loading…</div>;
  }
  if (userState.status === 'error') {
    return <div className="text-red-500 text-sm py-16 text-center">Could not load profile: {userState.message}</div>;
  }

  const user = userState.user;
  const initials = [user.givenName, user.surname].filter(Boolean).map((n) => n![0]).join('') ||
    user.displayName.split(' ').map((n) => n[0]).join('').slice(0, 2);

  // TODO: replace with fetch('/api/rentals/me') and fetch('/api/classes/me')
  const userRentals = MOCK_RENTALS.filter((r) => r.studentId === DEV_STUDENT_ID);
  const userClasses = MOCK_CLASSES.filter((c) => c.students.includes(DEV_STUDENT_ID));
  const overdueCount = userRentals.filter((r) => r.status === "Overdue").length;

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
            <div className="text-xl font-bold text-gray-900">{userRentals.length}</div>
            <div className="text-xs text-gray-400 mt-0.5">Rentals</div>
          </div>
          <div>
            <div className={`text-xl font-bold ${overdueCount > 0 ? "text-red-600" : "text-gray-900"}`}>
              {overdueCount}
            </div>
            <div className="text-xs text-gray-400 mt-0.5">Overdue</div>
          </div>
          <div>
            <div className="text-xl font-bold text-gray-900">{userClasses.length}</div>
            <div className="text-xs text-gray-400 mt-0.5">Classes</div>
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

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <section>
          <div className="flex items-center gap-2 mb-3">
            <BookOpen className="w-4 h-4 text-gray-400" />
            <h2 className="text-gray-800">Enrolled Classes</h2>
          </div>
          <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
            {userClasses.length > 0 ? (
              <ul className="divide-y divide-gray-100">
                {userClasses.map((c) => (
                  <li key={c.id} className="px-5 py-4 hover:bg-gray-50 transition-colors">
                    <p className="font-medium text-gray-900">{c.name}</p>
                    <p className="text-sm text-gray-400 mt-0.5">{c.students.length} students enrolled</p>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="px-5 py-8 text-center text-gray-400 text-sm">No classes enrolled.</div>
            )}
          </div>
        </section>

        <section>
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-4 h-4 text-gray-400" />
            <h2 className="text-gray-800">Current Rentals</h2>
          </div>
          <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
            {userRentals.length > 0 ? (
              <ul className="divide-y divide-gray-100">
                {userRentals.map((rental) => {
                  const gear = MOCK_GEAR.find((g) => g.id === rental.gearId);
                  const isOverdue = rental.status === "Overdue";
                  return (
                    <li key={rental.id} className="flex items-center gap-4 px-5 py-4 hover:bg-gray-50 transition-colors">
                      {gear && (
                        <img
                          src={gear.photo}
                          alt={gear.name}
                          className="w-12 h-12 rounded-lg object-cover shrink-0 bg-gray-100"
                        />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-gray-900 truncate">{gear?.name ?? "Unknown"}</p>
                        <p className="text-xs text-gray-400 mt-0.5">
                          Due {new Date(rental.dueDate).toLocaleDateString("en-US", { month: "long", day: "numeric" })}
                        </p>
                      </div>
                      <span
                        className={`flex items-center gap-1 text-xs font-medium px-2.5 py-1 rounded-full shrink-0 ${
                          isOverdue
                            ? "bg-red-50 text-red-600 border border-red-200"
                            : "bg-green-50 text-green-700 border border-green-200"
                        }`}
                      >
                        {isOverdue ? <AlertCircle className="w-3 h-3" /> : <CheckCircle className="w-3 h-3" />}
                        {rental.status}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <div className="px-5 py-8 text-center text-gray-400 text-sm">No active rentals.</div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
