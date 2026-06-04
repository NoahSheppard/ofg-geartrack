import { useState } from "react";
import { MOCK_GEAR } from "../data";
import { Clock, Package, X, Search } from "lucide-react";

const CATEGORY_COLORS: Record<string, string> = {
  Camera: "text-violet-600 bg-violet-50",
  Lens: "text-blue-600 bg-blue-50",
  Support: "text-teal-600 bg-teal-50",
  Lighting: "text-yellow-700 bg-yellow-50",
  Audio: "text-rose-600 bg-rose-50",
};

export function RentalPage() {
  const [selectedGearId, setSelectedGearId] = useState<string | null>(null);
  const [rentDuration, setRentDuration] = useState(1);
  const [searchQuery, setSearchQuery] = useState("");

  const filteredGear = MOCK_GEAR.filter(
    (g) =>
      g.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      g.category.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleRent = (e: React.FormEvent, gearId: string) => {
    e.preventDefault();
    alert(`Rental request submitted for ${rentDuration} day${rentDuration !== 1 ? "s" : ""}!`);
    setSelectedGearId(null);
    setRentDuration(1);
  };

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
        {filteredGear.map((gear) => {
          const catClass = CATEGORY_COLORS[gear.category] ?? "text-gray-600 bg-gray-100";
          const isSelected = selectedGearId === gear.id;
          const outOfStock = gear.stock === 0;

          return (
            <div
              key={gear.id}
              className="bg-white border border-gray-200 rounded-2xl overflow-hidden flex flex-col hover:shadow-md transition-shadow"
            >
              <div className="relative aspect-[16/9] overflow-hidden bg-gray-100">
                <img
                  src={gear.photo}
                  alt={gear.name}
                  className="w-full h-full object-cover"
                  style={outOfStock ? { filter: "grayscale(50%)" } : undefined}
                />
                <span className={`absolute top-3 left-3 text-xs font-medium px-2 py-0.5 rounded-full ${catClass}`}>
                  {gear.category}
                </span>
              </div>

              <div className="p-5 flex-1 flex flex-col">
                <h3 className="text-gray-900 mb-1">{gear.name}</h3>
                <p className="text-sm text-gray-500 mb-4 flex-1 line-clamp-2">{gear.description}</p>

                <div className="flex items-center gap-4 text-xs text-gray-400 mb-4 border-t border-gray-100 pt-3">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" /> Max {gear.maxRentDays} days
                  </span>
                  <span className="flex items-center gap-1">
                    <Package className="w-3.5 h-3.5" />
                    <span className={outOfStock ? "text-red-500" : gear.stock <= 2 ? "text-amber-600" : "text-green-600"}>
                      {outOfStock ? "Out of stock" : `${gear.stock} available`}
                    </span>
                  </span>
                </div>

                {isSelected ? (
                  <form onSubmit={(e) => handleRent(e, gear.id)} className="space-y-3">
                    <div className="bg-gray-50 border border-gray-200 rounded-xl p-3">
                      <div className="flex items-center justify-between mb-2">
                        <label className="text-xs font-medium text-gray-600">Duration</label>
                        <span className="text-sm font-semibold text-blue-600">
                          {rentDuration} day{rentDuration !== 1 ? "s" : ""}
                        </span>
                      </div>
                      <input
                        type="range"
                        min="1"
                        max={gear.maxRentDays}
                        value={rentDuration}
                        onChange={(e) => setRentDuration(parseInt(e.target.value))}
                        className="w-full accent-blue-600"
                      />
                      <div className="flex justify-between text-xs text-gray-400 mt-1">
                        <span>1 day</span>
                        <span>{gear.maxRentDays} days</span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="submit"
                        className="flex-1 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
                      >
                        Confirm
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
                    onClick={() => { setSelectedGearId(gear.id); setRentDuration(1); }}
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
