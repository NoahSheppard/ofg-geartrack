import { useEffect, useState } from 'react';

export type CurrentUser = {
  email: string;
  displayName: string;
  givenName?: string;
  surname?: string;
  role?: string;
  uid?: string;
};

type State =
  | { status: 'loading' }
  | { status: 'ok'; user: CurrentUser }
  | { status: 'error'; message: string };

// In dev (Vite), there's no real session, so fall back to the mock user.
// In production (served by Express), /api/me returns the SAML session user.
const IS_DEV = import.meta.env.DEV;

const DEV_MOCK: CurrentUser = {
  email: 'alex.j@hs.edu',
  displayName: 'Alex Johnson',
  givenName: 'Alex',
  surname: 'Johnson',
  role: 'student',
};

export function useCurrentUser(): State {
  const [state, setState] = useState<State>({ status: 'loading' });

  useEffect(() => {
    if (IS_DEV) {
      setState({ status: 'ok', user: DEV_MOCK });
      return;
    }

    fetch('/api/me', { credentials: 'include' })
      .then((r) => {
        if (r.status === 401) {
          window.location.href = '/login';
          return null;
        }
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((user) => {
        if (user) setState({ status: 'ok', user });
      })
      .catch((err) => setState({ status: 'error', message: err.message }));
  }, []);

  return state;
}
