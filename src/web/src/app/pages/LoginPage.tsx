import { useState } from "react";
import { Aperture, GraduationCap, ShieldAlert, BookUser } from "lucide-react";

async function devLogin(role: "student" | "teacher" | "admin") {
  const res = await fetch("/auth/dev-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ role }),
  });
  if (res.ok) {
    window.location.href = "/";
  }
}

export function LoginPage() {
  const [loading, setLoading] = useState<"student" | "teacher" | "admin" | null>(null);

  const handleDevLogin = async (role: "student" | "teacher" | "admin") => {
    setLoading(role);
    try {
      await devLogin(role);
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="min-h-screen bg-stone-50 flex items-center justify-center px-4">
      <div className="w-full max-w-sm bg-white border border-gray-200 rounded-2xl p-8 text-center space-y-6">
        <div className="flex items-center justify-center gap-2">
          <Aperture className="w-6 h-6 text-blue-600" />
          <span className="font-bold text-gray-900 tracking-tight text-lg">GearTrack</span>
        </div>

        <div>
          <h1 className="text-gray-900">Sign in</h1>
          <p className="text-sm text-gray-500 mt-1">
            Multimedia Department Equipment Rental &amp; Tracking System
          </p>
        </div>

        {import.meta.env.DEV ? (
          <div className="space-y-3">
            <p className="text-xs text-gray-400">Development sign-in (no SAML)</p>
            <button
              onClick={() => handleDevLogin("student")}
              disabled={loading !== null}
              className="w-full flex items-center justify-center gap-2 py-2.5 bg-gray-900 text-white rounded-lg text-sm font-medium hover:bg-gray-700 transition-colors disabled:opacity-50"
            >
              <GraduationCap className="w-4 h-4" />
              {loading === "student" ? "Signing in…" : "Continue as Student"}
            </button>
            <button
              onClick={() => handleDevLogin("teacher")}
              disabled={loading !== null}
              className="w-full flex items-center justify-center gap-2 py-2.5 border border-gray-200 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-50"
            >
              <BookUser className="w-4 h-4" />
              {loading === "teacher" ? "Signing in…" : "Continue as Teacher"}
            </button>
            <button
              onClick={() => handleDevLogin("admin")}
              disabled={loading !== null}
              className="w-full flex items-center justify-center gap-2 py-2.5 border border-gray-200 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-50"
            >
              <ShieldAlert className="w-4 h-4" />
              {loading === "admin" ? "Signing in…" : "Continue as Admin"}
            </button>
          </div>
        ) : (
          <a
            href="/login"
            className="block w-full py-2.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
          >
            Sign in with school account
          </a>
        )}
      </div>
    </div>
  );
}
