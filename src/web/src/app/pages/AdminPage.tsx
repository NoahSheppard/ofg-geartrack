import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Search, Package, Clock, AlertTriangle, CheckCircle, XCircle, X, ListChecks, PlusCircle, Upload } from "lucide-react";
import type { AdminStats, Gear, Category, PendingRental, ActiveRental } from "../types";

// ─── Modal shell ─────────────────────────────────────────────────────────────

function Modal({
  onClose,
  children,
  widthClass = "max-w-md",
}: {
  onClose: () => void;
  children: React.ReactNode;
  widthClass?: string;
}) {
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handleKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handleKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.35)" }}
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
    >
      <div className={`bg-white rounded-2xl shadow-2xl w-full ${widthClass} max-h-[85vh] flex flex-col overflow-hidden`}>
        {children}
      </div>
    </div>
  );
}

// ─── Reject modal ──────────────────────────────────────────────────────────────

function RejectModal({
  rental,
  onClose,
  onConfirm,
}: {
  rental: PendingRental;
  onClose: () => void;
  onConfirm: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");

  return (
    <Modal onClose={onClose}>
      <div className="flex items-start justify-between p-5 border-b border-gray-100">
        <div>
          <h2 className="text-gray-900">Reject Request</h2>
          <p className="text-sm text-gray-400 mt-0.5">
            {rental.studentName} · {rental.quantity} × {rental.gearName}
          </p>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>
      <div className="p-5 space-y-3">
        <label className="text-xs font-medium text-gray-600">Reason (required)</label>
        <textarea
          rows={3}
          autoFocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Let the student know why this request was rejected…"
          className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 resize-none"
        />
      </div>
      <div className="flex gap-2 p-5 pt-0">
        <button
          onClick={onClose}
          className="flex-1 py-2 border border-gray-200 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-50 transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onConfirm(reason.trim())}
          disabled={!reason.trim()}
          className="flex-1 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-colors disabled:opacity-50"
        >
          Reject Request
        </button>
      </div>
    </Modal>
  );
}

// ─── Add Gear form ──────────────────────────────────────────────────────────

const CONDITIONS = ["New", "Excellent", "Good", "Fair", "Poor"];
const NEW_CATEGORY = "__new__";

type GearFormValues = {
  name: string;
  categoryId: string;
  newCategoryName: string;
  manufacturer: string;
  modelNo: string;
  serialNo: string;
  type: string;
  condition: string;
  quantityTotal: string;
  quantityAvailable: string;
  description: string;
  imageUrl: string;
};

const EMPTY_GEAR_FORM: GearFormValues = {
  name: "",
  categoryId: "",
  newCategoryName: "",
  manufacturer: "",
  modelNo: "",
  serialNo: "",
  type: "",
  condition: "Good",
  quantityTotal: "1",
  quantityAvailable: "1",
  description: "",
  imageUrl: "",
};

function gearToFormValues(g: Gear, categories: Category[]): GearFormValues {
  const category = categories.find((c) => c.name === g.category);
  return {
    name: g.name,
    categoryId: category ? String(category.id) : "",
    newCategoryName: "",
    manufacturer: g.manufacturer ?? "",
    modelNo: g.modelNo ?? "",
    serialNo: g.serialNo ?? "",
    type: g.type ?? "",
    condition: g.condition ?? "Good",
    quantityTotal: String(g.quantityTotal),
    quantityAvailable: String(g.quantityAvailable),
    description: g.description ?? "",
    imageUrl: g.imageUrl ?? "",
  };
}

// ─── Image field (URL or file upload) ───────────────────────────────────────

function ImageField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);

  const handleFile = (file: File) => {
    if (!file.type.startsWith("image/")) {
      toast.error("Please choose an image file");
      return;
    }
    const reader = new FileReader();
    reader.onload = async () => {
      if (typeof reader.result !== "string") return;
      setUploading(true);
      try {
        const res = await fetch("/api/admin/gear/upload-image", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ dataUrl: reader.result }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          toast.error(body.error ?? "Failed to upload image");
          return;
        }
        onChange(body.url);
      } catch {
        toast.error("Failed to upload image");
      } finally {
        setUploading(false);
      }
    };
    reader.onerror = () => toast.error("Failed to read image file");
    reader.readAsDataURL(file);
  };

  return (
    <div className="sm:col-span-2">
      <label className="text-xs font-medium text-gray-600">Image</label>
      <div className="mt-1 flex items-start gap-3">
        <div className="w-16 h-16 rounded-lg shrink-0 bg-gray-100 border border-gray-200 flex items-center justify-center overflow-hidden">
          {value ? (
            <img src={value} alt="" className="w-full h-full object-cover" />
          ) : (
            <Package className="w-5 h-5 text-gray-300" />
          )}
        </div>
        <div className="flex-1 space-y-2">
          <input
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder="Paste an image URL…"
            className="w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
          />
          <div className="flex items-center gap-3">
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFile(file);
                e.target.value = "";
              }}
            />
            <button
              type="button"
              disabled={uploading}
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center gap-1.5 px-3 py-1.5 border border-gray-200 rounded-lg text-xs font-medium text-gray-600 hover:bg-gray-50 transition-colors disabled:opacity-50"
            >
              <Upload className="w-3.5 h-3.5" /> {uploading ? "Uploading…" : "Upload image"}
            </button>
            {value && (
              <button
                type="button"
                onClick={() => onChange("")}
                className="text-xs text-gray-400 hover:text-red-500 transition-colors"
              >
                Remove
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Shared gear form fields ────────────────────────────────────────────────

function GearFormFields({
  values,
  update,
  categories,
  showAvailable,
}: {
  values: GearFormValues;
  update: (field: keyof GearFormValues, value: string) => void;
  categories: Category[];
  showAvailable?: boolean;
}) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <div>
        <label className="text-xs font-medium text-gray-600">Name *</label>
        <input
          type="text"
          value={values.name}
          onChange={(e) => update("name", e.target.value)}
          placeholder="e.g. Go-Pro"
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        />
      </div>

      <div>
        <label className="text-xs font-medium text-gray-600">Category</label>
        <select
          value={values.categoryId}
          onChange={(e) => update("categoryId", e.target.value)}
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        >
          <option value="">Uncategorised</option>
          {categories.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
          <option value={NEW_CATEGORY}>+ New category…</option>
        </select>
      </div>

      {values.categoryId === NEW_CATEGORY && (
        <div className="sm:col-span-2">
          <label className="text-xs font-medium text-gray-600">New category name</label>
          <input
            type="text"
            value={values.newCategoryName}
            onChange={(e) => update("newCategoryName", e.target.value)}
            placeholder="e.g. Multi-Media"
            className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
          />
        </div>
      )}

      <div>
        <label className="text-xs font-medium text-gray-600">Manufacturer</label>
        <input
          type="text"
          value={values.manufacturer}
          onChange={(e) => update("manufacturer", e.target.value)}
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        />
      </div>

      <div>
        <label className="text-xs font-medium text-gray-600">Model No.</label>
        <input
          type="text"
          value={values.modelNo}
          onChange={(e) => update("modelNo", e.target.value)}
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        />
      </div>

      <div>
        <label className="text-xs font-medium text-gray-600">Serial No. / OFG No.</label>
        <input
          type="text"
          value={values.serialNo}
          onChange={(e) => update("serialNo", e.target.value)}
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        />
      </div>

      <div>
        <label className="text-xs font-medium text-gray-600">Type</label>
        <input
          type="text"
          value={values.type}
          onChange={(e) => update("type", e.target.value)}
          placeholder="e.g. Digital Camera"
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        />
      </div>

      <div>
        <label className="text-xs font-medium text-gray-600">Condition</label>
        <select
          value={values.condition}
          onChange={(e) => update("condition", e.target.value)}
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        >
          {CONDITIONS.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
      </div>

      <div className={showAvailable ? "" : "sm:col-span-2"}>
        <label className="text-xs font-medium text-gray-600">{showAvailable ? "Total Quantity *" : "Quantity *"}</label>
        <input
          type="number"
          min={0}
          value={values.quantityTotal}
          onChange={(e) => update("quantityTotal", e.target.value)}
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
        />
      </div>

      {showAvailable && (
        <div>
          <label className="text-xs font-medium text-gray-600">Available *</label>
          <input
            type="number"
            min={0}
            max={Number(values.quantityTotal) || undefined}
            value={values.quantityAvailable}
            onChange={(e) => update("quantityAvailable", e.target.value)}
            className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
          />
        </div>
      )}

      <ImageField value={values.imageUrl} onChange={(v) => update("imageUrl", v)} />

      <div className="sm:col-span-2">
        <label className="text-xs font-medium text-gray-600">Notes / Specifications</label>
        <textarea
          rows={2}
          value={values.description}
          onChange={(e) => update("description", e.target.value)}
          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 resize-none"
        />
      </div>
    </div>
  );
}

function AddGearForm({
  categories,
  onAdded,
}: {
  categories: Category[];
  onAdded: () => void;
}) {
  const [values, setValues] = useState<GearFormValues>(EMPTY_GEAR_FORM);
  const [submitting, setSubmitting] = useState(false);

  const update = (field: keyof GearFormValues, value: string) =>
    setValues((v) => ({ ...v, [field]: value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const name = values.name.trim();
    const qty = Number(values.quantityTotal);

    if (!name) {
      toast.error("Item name is required");
      return;
    }
    if (!Number.isInteger(qty) || qty < 0) {
      toast.error("Quantity must be a whole number ≥ 0");
      return;
    }
    if (values.categoryId === NEW_CATEGORY && !values.newCategoryName.trim()) {
      toast.error("Enter a name for the new category");
      return;
    }

    setSubmitting(true);
    try {
      let categoryId: number | null = values.categoryId ? Number(values.categoryId) : null;

      if (values.categoryId === NEW_CATEGORY) {
        const res = await fetch("/api/admin/categories", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ name: values.newCategoryName.trim() }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          toast.error(body.error ?? "Failed to create category");
          return;
        }
        categoryId = body.id;
      }

      const res = await fetch("/api/admin/gear", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name,
          categoryId,
          description: values.description.trim() || undefined,
          manufacturer: values.manufacturer.trim() || undefined,
          modelNo: values.modelNo.trim() || undefined,
          serialNo: values.serialNo.trim() || undefined,
          type: values.type.trim() || undefined,
          condition: values.condition,
          quantityTotal: qty,
          imageUrl: values.imageUrl.trim() || undefined,
        }),
      });
      const body = await res.json().catch(() => ({}));

      if (!res.ok) {
        toast.error(body.error ?? "Failed to add gear");
        return;
      }

      toast.success(`Added "${name}" to inventory`);
      setValues(EMPTY_GEAR_FORM);
      onAdded();
    } catch {
      toast.error("Failed to add gear");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="p-5 space-y-4 max-w-2xl">
      <GearFormFields values={values} update={update} categories={categories} />

      <button
        type="submit"
        disabled={submitting}
        className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors disabled:opacity-50"
      >
        <PlusCircle className="w-4 h-4" />
        {submitting ? "Adding…" : "Add Gear Item"}
      </button>
    </form>
  );
}

// ─── Gear detail / edit modal ───────────────────────────────────────────────

function GearEditModal({
  gear,
  categories,
  onClose,
  onSaved,
}: {
  gear: Gear;
  categories: Category[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [values, setValues] = useState<GearFormValues>(() => gearToFormValues(gear, categories));
  const [submitting, setSubmitting] = useState(false);

  const update = (field: keyof GearFormValues, value: string) =>
    setValues((v) => ({ ...v, [field]: value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const name = values.name.trim();
    const qtyTotal = Number(values.quantityTotal);
    const qtyAvailable = Number(values.quantityAvailable);

    if (!name) {
      toast.error("Item name is required");
      return;
    }
    if (!Number.isInteger(qtyTotal) || qtyTotal < 0) {
      toast.error("Total quantity must be a whole number ≥ 0");
      return;
    }
    if (!Number.isInteger(qtyAvailable) || qtyAvailable < 0 || qtyAvailable > qtyTotal) {
      toast.error("Available quantity must be between 0 and the total quantity");
      return;
    }
    if (values.categoryId === NEW_CATEGORY && !values.newCategoryName.trim()) {
      toast.error("Enter a name for the new category");
      return;
    }

    setSubmitting(true);
    try {
      let categoryId: number | null = values.categoryId ? Number(values.categoryId) : null;

      if (values.categoryId === NEW_CATEGORY) {
        const res = await fetch("/api/admin/categories", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ name: values.newCategoryName.trim() }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          toast.error(body.error ?? "Failed to create category");
          return;
        }
        categoryId = body.id;
      }

      const res = await fetch(`/api/admin/gear/${gear.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name,
          categoryId,
          description: values.description.trim() || null,
          manufacturer: values.manufacturer.trim() || null,
          modelNo: values.modelNo.trim() || null,
          serialNo: values.serialNo.trim() || null,
          type: values.type.trim() || null,
          condition: values.condition,
          quantityTotal: qtyTotal,
          quantityAvailable: qtyAvailable,
          imageUrl: values.imageUrl.trim() || null,
        }),
      });
      const body = await res.json().catch(() => ({}));

      if (!res.ok) {
        toast.error(body.error ?? "Failed to update gear");
        return;
      }

      toast.success(`Saved "${name}"`);
      onSaved();
      onClose();
    } catch {
      toast.error("Failed to update gear");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal onClose={onClose} widthClass="max-w-2xl">
      <div className="flex items-start justify-between p-5 border-b border-gray-100">
        <div>
          <h2 className="text-gray-900">Edit Gear</h2>
          <p className="text-sm text-gray-400 mt-0.5">{gear.name}</p>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>
      <form onSubmit={handleSubmit} className="p-5 space-y-4 overflow-y-auto">
        <GearFormFields values={values} update={update} categories={categories} showAvailable />

        <div className="flex gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="flex-1 py-2 border border-gray-200 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="flex-1 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors disabled:opacity-50"
          >
            {submitting ? "Saving…" : "Save Changes"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

const TABS = [
  { id: "pending" as const, label: "Pending Requests", icon: Clock },
  { id: "active" as const, label: "Active Rentals", icon: Package },
  { id: "gear" as const, label: "Gear Inventory", icon: ListChecks },
  { id: "add" as const, label: "Add Gear", icon: PlusCircle },
];

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function AdminPage() {
  const [activeTab, setActiveTab] = useState<"pending" | "active" | "gear" | "add">("pending");
  const [search, setSearch] = useState("");

  const [stats, setStats] = useState<AdminStats | null>(null);
  const [pending, setPending] = useState<PendingRental[]>([]);
  const [active, setActive] = useState<ActiveRental[]>([]);
  const [gear, setGear] = useState<Gear[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [rejectTarget, setRejectTarget] = useState<PendingRental | null>(null);
  const [editTarget, setEditTarget] = useState<Gear | null>(null);

  const refreshAll = async () => {
    try {
      const [statsRes, pendingRes, activeRes, gearRes, categoriesRes] = await Promise.all([
        fetch("/api/admin/stats", { credentials: "include" }),
        fetch("/api/admin/rentals/pending", { credentials: "include" }),
        fetch("/api/admin/rentals/active", { credentials: "include" }),
        fetch("/api/admin/gear", { credentials: "include" }),
        fetch("/api/admin/categories", { credentials: "include" }),
      ]);

      if (!statsRes.ok || !pendingRes.ok || !activeRes.ok || !gearRes.ok || !categoriesRes.ok) {
        throw new Error("Failed to load admin data");
      }

      setStats(await statsRes.json());
      setPending(await pendingRes.json());
      setActive(await activeRes.json());
      setGear(await gearRes.json());
      setCategories(await categoriesRes.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load admin data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshAll();
  }, []);

  const handleApprove = async (rental: PendingRental) => {
    if (!window.confirm(`Approve ${rental.studentName}'s request for ${rental.quantity} × ${rental.gearName}?`)) return;

    const res = await fetch(`/api/admin/rentals/${rental.id}/approve`, { method: "PATCH", credentials: "include" });
    const body = await res.json().catch(() => ({}));

    if (!res.ok) {
      toast.error(body.error ?? "Failed to approve request");
      return;
    }

    toast.success("Request approved");
    refreshAll();
  };

  const handleReject = async (reason: string) => {
    if (!rejectTarget) return;

    const res = await fetch(`/api/admin/rentals/${rejectTarget.id}/reject`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ reason }),
    });
    const body = await res.json().catch(() => ({}));

    if (!res.ok) {
      toast.error(body.error ?? "Failed to reject request");
      return;
    }

    toast.success("Request rejected");
    setRejectTarget(null);
    refreshAll();
  };

  const handleReturn = async (rental: ActiveRental) => {
    if (!window.confirm(`Mark ${rental.quantity} × ${rental.gearName} (${rental.studentName}) as returned?`)) return;

    const res = await fetch(`/api/admin/rentals/${rental.id}/return`, { method: "PATCH", credentials: "include" });
    const body = await res.json().catch(() => ({}));

    if (!res.ok) {
      toast.error(body.error ?? "Failed to mark as returned");
      return;
    }

    toast.success("Marked as returned");
    refreshAll();
  };

  if (loading) {
    return <div className="text-gray-400 text-sm py-16 text-center">Loading admin dashboard…</div>;
  }
  if (error) {
    return <div className="text-red-500 text-sm py-16 text-center">Could not load admin data: {error}</div>;
  }

  const filteredPending = pending.filter(
    (r) =>
      r.studentName.toLowerCase().includes(search.toLowerCase()) ||
      r.gearName.toLowerCase().includes(search.toLowerCase())
  );
  const filteredActive = active.filter(
    (r) =>
      r.studentName.toLowerCase().includes(search.toLowerCase()) ||
      r.gearName.toLowerCase().includes(search.toLowerCase())
  );
  const filteredGear = gear.filter(
    (g) =>
      g.name.toLowerCase().includes(search.toLowerCase()) ||
      (g.category ?? "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {rejectTarget && (
        <RejectModal rental={rejectTarget} onClose={() => setRejectTarget(null)} onConfirm={handleReject} />
      )}

      {editTarget && (
        <GearEditModal
          gear={editTarget}
          categories={categories}
          onClose={() => setEditTarget(null)}
          onSaved={refreshAll}
        />
      )}

      {/* Page header */}
      <div>
        <h1 className="text-gray-900">Admin Dashboard</h1>
        <p className="text-gray-500 text-sm mt-0.5">Multimedia Department · Equipment Rentals</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Pending Requests", value: stats?.pending ?? 0 },
          { label: "Active Rentals", value: stats?.active ?? 0 },
          { label: "Overdue", value: stats?.overdue ?? 0, warn: (stats?.overdue ?? 0) > 0 },
          { label: "Total Gear", value: stats?.totalGear ?? 0 },
        ].map((s) => (
          <div
            key={s.label}
            className={`rounded-xl border px-4 py-3 bg-white ${s.warn ? "border-red-200" : "border-gray-200"}`}
          >
            <div className={`text-2xl font-bold ${s.warn ? "text-red-600" : "text-gray-900"}`}>{s.value}</div>
            <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs + search */}
      <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
        <div className="flex border border-gray-200 rounded-lg overflow-hidden bg-white">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => { setActiveTab(id); setSearch(""); }}
              className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium transition-colors border-r last:border-r-0 border-gray-200 ${
                activeTab === id ? "bg-gray-900 text-white" : "text-gray-600 hover:bg-gray-50"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </button>
          ))}
        </div>
        {activeTab !== "add" && (
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              className="pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 w-48"
              placeholder="Search…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        )}
      </div>

      {/* Table */}
      <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
        {activeTab === "pending" && (
          <table className="min-w-full">
            <thead className="border-b border-gray-100 bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Student</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Item</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Dates</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filteredPending.map((r) => (
                <tr key={r.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-5 py-4">
                    <p className="font-medium text-gray-900 text-sm">{r.studentName}</p>
                    <p className="text-xs text-gray-400">{r.studentEmail}</p>
                  </td>
                  <td className="px-5 py-4">
                    <p className="text-sm text-gray-800">{r.quantity} × {r.gearName}</p>
                    <p className="text-xs text-gray-400">{r.quantityAvailable} available</p>
                  </td>
                  <td className="px-5 py-4 text-sm text-gray-500">
                    {formatDate(r.rentalStart)} – {formatDate(r.returnDue)}
                  </td>
                  <td className="px-5 py-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleApprove(r)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-green-50 text-green-700 border border-green-200 hover:bg-green-100 transition-colors"
                      >
                        <CheckCircle className="w-3.5 h-3.5" /> Approve
                      </button>
                      <button
                        onClick={() => setRejectTarget(r)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-50 text-red-600 border border-red-200 hover:bg-red-100 transition-colors"
                      >
                        <XCircle className="w-3.5 h-3.5" /> Reject
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === "active" && (
          <table className="min-w-full">
            <thead className="border-b border-gray-100 bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Student</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Item</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Due</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filteredActive.map((r) => (
                <tr key={r.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-5 py-4">
                    <p className="font-medium text-gray-900 text-sm">{r.studentName}</p>
                    <p className="text-xs text-gray-400">{r.studentEmail}</p>
                  </td>
                  <td className="px-5 py-4 text-sm text-gray-800">{r.quantity} × {r.gearName}</td>
                  <td className="px-5 py-4">
                    {r.isOverdue ? (
                      <span className="inline-flex items-center gap-1 text-xs text-red-600 font-medium">
                        <AlertTriangle className="w-3.5 h-3.5" /> Overdue · {formatDate(r.returnDue)}
                      </span>
                    ) : (
                      <span className="text-sm text-gray-500">Due {formatDate(r.returnDue)}</span>
                    )}
                  </td>
                  <td className="px-5 py-4 text-right">
                    <button
                      onClick={() => handleReturn(r)}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-900 text-white hover:bg-gray-700 transition-colors"
                    >
                      Mark as Returned
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === "gear" && (
          <table className="min-w-full">
            <thead className="border-b border-gray-100 bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Item</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Manufacturer / Model</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Serial / OFG No.</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Availability</th>
                <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Condition</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filteredGear.map((g) => (
                <tr
                  key={g.id}
                  onClick={() => setEditTarget(g)}
                  className="hover:bg-gray-50 transition-colors cursor-pointer"
                >
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-3">
                      {g.imageUrl ? (
                        <img src={g.imageUrl} alt={g.name} className="w-10 h-10 rounded-lg object-cover shrink-0 bg-gray-100" />
                      ) : (
                        <div className="w-10 h-10 rounded-lg shrink-0 bg-gray-100 flex items-center justify-center">
                          <Package className="w-4 h-4 text-gray-300" />
                        </div>
                      )}
                      <div>
                        <p className="font-medium text-gray-900 text-sm">{g.name}</p>
                        <p className="text-xs text-gray-400">{g.category}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-4 text-sm text-gray-500">
                    {[g.manufacturer, g.modelNo].filter(Boolean).join(" · ") || "—"}
                  </td>
                  <td className="px-5 py-4 text-sm text-gray-500">{g.serialNo || "—"}</td>
                  <td className="px-5 py-4 text-sm text-gray-500">
                    {g.quantityAvailable} of {g.quantityTotal} available
                  </td>
                  <td className="px-5 py-4 text-sm text-gray-500">{g.condition}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === "add" && (
          <AddGearForm categories={categories} onAdded={refreshAll} />
        )}

        {((activeTab === "pending" && filteredPending.length === 0) ||
          (activeTab === "active" && filteredActive.length === 0) ||
          (activeTab === "gear" && filteredGear.length === 0)) && (
          <div className="px-5 py-12 text-center text-gray-400 text-sm">Nothing to show here.</div>
        )}
      </div>
    </div>
  );
}
