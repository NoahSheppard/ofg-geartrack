// Shared types mirroring the JSON shapes returned by /api/* (see src/index.js).

export type CurrentUser = {
  email: string;
  displayName: string;
  givenName?: string;
  surname?: string;
  role?: string;
  uid?: string;
};

export type Gear = {
  id: number;
  name: string;
  description: string | null;
  category: string | null;
  quantityTotal: number;
  quantityAvailable: number;
  condition: string;
  imageUrl: string | null;
  manufacturer: string | null;
  modelNo: string | null;
  serialNo: string | null;
  type: string | null;
};

export type Category = {
  id: number;
  name: string;
  description: string | null;
};

export type RentalStatus = 'pending' | 'approved' | 'rejected' | 'returned' | 'overdue';

export type Rental = {
  id: number;
  gearId: number;
  quantity: number;
  rentalStart: string;
  returnDue: string;
  returnActual: string | null;
  rejectionReason: string | null;
  status: RentalStatus;
  gearName: string;
  gearImage: string | null;
  gearCategory: string | null;
};

export type PendingRental = {
  id: number;
  quantity: number;
  rentalStart: string;
  returnDue: string;
  createdAt: string;
  studentName: string;
  studentEmail: string;
  gearId: number;
  gearName: string;
  quantityAvailable: number;
};

export type ActiveRental = {
  id: number;
  quantity: number;
  rentalStart: string;
  returnDue: string;
  studentName: string;
  studentEmail: string;
  gearId: number;
  gearName: string;
  isOverdue: number;
};

export type AdminStats = {
  pending: number;
  active: number;
  overdue: number;
  totalGear: number;
};
