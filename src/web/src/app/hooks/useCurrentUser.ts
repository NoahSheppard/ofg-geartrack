import { useEffect, useState } from 'react';
import type { CurrentUser } from '../types';

export type { CurrentUser };

type State =
  | { status: 'loading' }
  | { status: 'ok'; user: CurrentUser }
  | { status: 'unauthenticated' }
  | { status: 'error'; message: string };

export function useCurrentUser(): State {
  const [state, setState] = useState<State>({ status: 'loading' });

  useEffect(() => {
    fetch('/api/me', { credentials: 'include' })
      .then((r) => {
        if (r.status === 401) {
          setState({ status: 'unauthenticated' });
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
