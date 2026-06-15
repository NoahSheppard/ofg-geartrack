import { Outlet, NavLink, Navigate } from "react-router";
import { Aperture, Package, User, Users, ShieldAlert, LogOut } from "lucide-react";
import { useCurrentUser } from "./hooks/useCurrentUser";

const NAV_LINKS = [
  { to: "/", label: "Rent Gear", icon: Package },
  { to: "/profile", label: "My Profile", icon: User },
  { to: "/classes", label: "My Classes", icon: Users, studentOnly: true },
  { to: "/admin", label: "Admin", icon: ShieldAlert, adminOnly: true },
];

export function Layout() {
  const userState = useCurrentUser();

  if (userState.status === 'loading') {
    return <div className="text-gray-400 text-sm py-16 text-center">Loading…</div>;
  }
  if (userState.status === 'unauthenticated') {
    return <Navigate to="/login" replace />;
  }
  if (userState.status === 'error') {
    return <div className="text-red-500 text-sm py-16 text-center">Could not load session: {userState.message}</div>;
  }

  const user = userState.user;
  const isAdmin = user.role === 'admin' || user.role === 'teacher';

  const initials = [user.givenName, user.surname].filter(Boolean).map((n) => n![0]).join('') ||
    user.displayName.split(' ').map((n) => n[0]).join('').slice(0, 2);

  return (
    <div className="min-h-screen bg-stone-50">
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-14">
            <NavLink to="/" className="flex items-center gap-2">
              <div className="flex items-center gap-2">
                <Aperture className="w-5 h-5 text-blue-600" />
                <span className="font-bold text-gray-900 tracking-tight">GearTrack</span>
              </div>
            </NavLink>

            <div className="flex items-center gap-1">
              {NAV_LINKS.filter((link) => (!link.adminOnly || isAdmin) && (!link.studentOnly || !isAdmin)).map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === "/"}
                  className={({ isActive }) =>
                    `flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      isActive
                        ? "bg-blue-50 text-blue-700"
                        : "text-gray-500 hover:text-gray-800 hover:bg-gray-100"
                    }`
                  }
                >
                  <Icon className="w-3.5 h-3.5" />
                  {label}
                </NavLink>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <NavLink to="/profile" title={user.displayName}>
                <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold cursor-pointer select-none">
                  {initials}
                </div>
              </NavLink>
              <a
                href="/logout"
                title="Log out"
                className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-sm font-medium text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </a>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto py-8 px-4 sm:px-6">
        <Outlet />
      </main>
    </div>
  );
}
