import { createBrowserRouter } from "react-router";
import { Layout } from "./Layout";
import { RentalPage } from "./pages/RentalPage";
import { ProfilePage } from "./pages/ProfilePage";
import { AdminPage } from "./pages/AdminPage";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: RentalPage },
      { path: "profile", Component: ProfilePage },
      { path: "admin", Component: AdminPage },
    ],
  },
]);
