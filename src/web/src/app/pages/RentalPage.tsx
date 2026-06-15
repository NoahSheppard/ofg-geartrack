import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { Clock, Package, X, Search } from "lucide-react";
import type { Gear } from "../types";

const CATEGORY_COLORS: Record<string, string> = {
  Cameras: "text-violet-600 bg-violet-50",
  Lenses: "text-blue-600 bg-blue-50",
  "Support & Grip": "text-teal-600 bg-teal-50",
  Lighting: "text-yellow-700 bg-yellow-50",
  Audio: "text-rose-600 bg-rose-50",
};

type RentalFormValues = {
  quantity: number;
  rentalStart: string;
  returnDue: string;
  purpose: string;
};

function todayISO() {
  return new Date().toISOString().split("T")[0];
}

function tomorrowISO() {
  return new Date(Date.now() + 86_400_000).toISOString().split("T")[0];
}

export function RentalPage() {
  const [gear, setGear] = useState<Gear[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedGearId, setSelectedGearId] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const {
    register,
    handleSubmit,
    reset,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<RentalFormValues>({
    defaultValues: { quantity: 1, rentalStart: todayISO(), returnDue: tomorrowISO(), purpose: "" },
  });

  const rentalStart = watch("rentalStart");

  useEffect(() => {
    fetch("/api/gear", { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setGear)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const filteredGear = gear.filter(
    (g) =>
      g.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (g.category ?? "").toLowerCase().includes(searchQuery.toLowerCase())
  );

  const openRequestForm = (item: Gear) => {
    setSelectedGearId(item.id);
    reset({ quantity: 1, rentalStart: todayISO(), returnDue: tomorrowISO(), purpose: "" });
  };

  const onSubmit = async (item: Gear, values: RentalFormValues) => {
    try {
      const res = await fetch("/api/rentals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          gearId: item.id,
          quantity: Number(values.quantity),
          rentalStart: values.rentalStart,
          returnDue: values.returnDue,
          purpose: values.purpose || undefined,
        }),
      });

      const body = await res.json().catch(() => ({}));

      if (!res.ok) {
        toast.error(body.error ?? "Failed to submit request");
        return;
      }

      toast.success("Request submitted — pending approval");
      setSelectedGearId(null);
    } catch {
      toast.error("Failed to submit request");
    }
  };

  if (loading) {
    return <div className="text-gray-400 text-sm py-16 text-center">Loading gear catalogue…</div>;
  }
  if (error) {
    return <div className="text-red-500 text-sm py-16 text-center">Could not load gear: {error}</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-gray-900">Gear Catalog</h1>
          <p className="text-gray-500 text-sm mt-0.5">Browse and request equipment for your projects</p>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search gear…"
            className="pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 w-52"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredGear.map((item) => {
          const catClass = CATEGORY_COLORS[item.category ?? ""] ?? "text-gray-600 bg-gray-100";
          const isSelected = selectedGearId === item.id;
          const outOfStock = item.quantityAvailable === 0;

          return (
            <div
              key={item.id}
              className="bg-white border border-gray-200 rounded-2xl overflow-hidden flex flex-col hover:shadow-md transition-shadow"
            >
              <div className="relative aspect-[16/9] overflow-hidden bg-gray-100">
                {item.imageUrl ? (
                  <img
                    src={item.imageUrl}
                    alt={item.name}
                    className="w-full h-full object-cover"
                    style={outOfStock ? { filter: "grayscale(50%)" } : undefined}
                  />
                ) : (
                  <div className="w-full h-full flex items-center justify-center">
                    <Package className="w-8 h-8 text-gray-300" />
                  </div>
                )}
                {item.category && (
                  <span className={`absolute top-3 left-3 text-xs font-medium px-2 py-0.5 rounded-full ${catClass}`}>
                    {item.category}
                  </span>
                )}
              </div>

              <div className="p-5 flex-1 flex flex-col">
                <h3 className="text-gray-900 mb-1">{item.name}</h3>
                <p className="text-sm text-gray-500 mb-4 flex-1 line-clamp-2">{item.description}</p>

                <div className="flex items-center gap-4 text-xs text-gray-400 mb-4 border-t border-gray-100 pt-3">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" /> Condition: {item.condition}
                  </span>
                  <span className="flex items-center gap-1">
                    <Package className="w-3.5 h-3.5" />
                    <span className={outOfStock ? "text-red-500" : item.quantityAvailable <= 1 ? "text-amber-600" : "text-green-600"}>
                      {outOfStock ? "Out of stock" : `${item.quantityAvailable} of ${item.quantityTotal} available`}
                    </span>
                  </span>
                </div>

                {isSelected ? (
                  <form onSubmit={handleSubmit((values) => onSubmit(item, values))} className="space-y-3">
                    <div className="bg-gray-50 border border-gray-200 rounded-xl p-3 space-y-3">
                      <div>
                        <label className="text-xs font-medium text-gray-600">Quantity</label>
                        <input
                          type="number"
                          min={1}
                          max={item.quantityAvailable}
                          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
                          {...register("quantity", {
                            required: true,
                            valueAsNumber: true,
                            min: 1,
                            max: item.quantityAvailable,
                          })}
                        />
                        {errors.quantity && (
                          <p className="text-xs text-red-500 mt-1">
                            Enter a quantity between 1 and {item.quantityAvailable}.
                          </p>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <label className="text-xs font-medium text-gray-600">Pickup date</label>
                          <input
                            type="date"
                            min={todayISO()}
                            className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
                            {...register("rentalStart", { required: true })}
                          />
                        </div>
                        <div>
                          <label className="text-xs font-medium text-gray-600">Return by</label>
                          <input
                            type="date"
                            min={rentalStart}
                            className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400"
                            {...register("returnDue", {
                              required: true,
                              validate: (v) => v > rentalStart || "Must be after the pickup date",
                            })}
                          />
                          {errors.returnDue && (
                            <p className="text-xs text-red-500 mt-1">{errors.returnDue.message}</p>
                          )}
                        </div>
                      </div>

                      <div>
                        <label className="text-xs font-medium text-gray-600">Purpose (optional)</label>
                        <textarea
                          rows={2}
                          placeholder="e.g. Filming a short documentary for Media Studies"
                          className="mt-1 w-full px-3 py-1.5 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 resize-none"
                          {...register("purpose")}
                        />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="submit"
                        disabled={isSubmitting}
                        className="flex-1 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors disabled:opacity-50"
                      >
                        {isSubmitting ? "Submitting…" : "Submit Request"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setSelectedGearId(null)}
                        className="px-3 py-2 border border-gray-200 rounded-lg text-gray-500 hover:bg-gray-50 transition-colors"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </form>
                ) : (
                  <button
                    onClick={() => openRequestForm(item)}
                    disabled={outOfStock}
                    className={`w-full py-2.5 rounded-lg text-sm font-medium transition-colors ${
                      outOfStock
                        ? "bg-gray-100 text-gray-400 cursor-not-allowed"
                        : "bg-gray-900 text-white hover:bg-gray-700"
                    }`}
                  >
                    {outOfStock ? "Unavailable" : "Request Rental"}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {filteredGear.length === 0 && (
        <div className="text-center py-16 text-gray-400">
          <Package className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">No gear matched your search.</p>
        </div>
      )}
    </div>
  );
}
