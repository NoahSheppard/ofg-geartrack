import { Outlet, NavLink } from "react-router";
import { Aperture, Package, User, ShieldAlert } from "lucide-react";
import { useCurrentUser } from "./hooks/useCurrentUser";

const NAV_LINKS = [
  { to: "/", label: "Rent Gear", icon: Package },
  { to: "/profile", label: "My Profile", icon: User },
  { to: "/admin", label: "Admin", icon: ShieldAlert },
];

export function Layout() {
  const userState = useCurrentUser();
  const user = userState.status === 'ok' ? userState.user : null;

  const initials = user
    ? [user.givenName, user.surname].filter(Boolean).map((n) => n![0]).join('') ||
      user.displayName.split(' ').map((n) => n[0]).join('').slice(0, 2)
    : '…';

  return (
    <div className="min-h-screen bg-stone-50">
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center gap-2">
              <Aperture className="w-5 h-5 text-blue-600" />
              <span className="font-bold text-gray-900 tracking-tight">MediaGear</span>
            </div>

            <div className="flex items-center gap-1">
              {NAV_LINKS.map(({ to, label, icon: Icon }) => (
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

            <div
              className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold cursor-pointer select-none"
              title={user?.displayName}
            >
              {initials}
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto py-8 px-4 sm:px-6">
        {/* Pass user down via context if needed, or each page calls useCurrentUser() itself */}
        <Outlet />
      </main>
    </div>
  );
}
