import { createBrowserRouter } from "react-router";
import { Layout } from "./Layout";
import { RentalPage } from "./pages/RentalPage";
import { ProfilePage } from "./pages/ProfilePage";
import { ClassesPage } from "./pages/ClassesPage";
import { AdminPage } from "./pages/AdminPage";
import { LoginPage } from "./pages/LoginPage";

export const router = createBrowserRouter([
  { path: "/login", Component: LoginPage },
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: RentalPage },
      { path: "profile", Component: ProfilePage },
      { path: "classes", Component: ClassesPage },
      { path: "admin", Component: AdminPage },
    ],
  },
]);
