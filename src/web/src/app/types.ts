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
  classId: number | null;
  className: string | null;
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
  classId: number | null;
  className: string | null;
};

export type AdminStats = {
  pending: number;
  active: number;
  overdue: number;
  totalGear: number;
};

export type ClassSummary = {
  id: number;
  name: string;
};

export type ClassListItem = {
  id: number;
  name: string;
  description: string | null;
  teacherCount: number;
  studentCount: number;
};

export type ClassMember = {
  id: number;
  displayName: string;
  email: string;
  role: string;
};

export type ClassRental = {
  id: number;
  quantity: number;
  rentalStart: string;
  returnDue: string;
  status: RentalStatus;
  studentName: string;
  gearName: string;
};

export type ClassDetail = {
  id: number;
  name: string;
  description: string | null;
  teachers: ClassMember[];
  students: ClassMember[];
  rentals: ClassRental[];
};

export type MyClassRental = {
  id: number;
  quantity: number;
  rentalStart: string;
  returnDue: string;
  status: RentalStatus;
  gearName: string;
};

export type MyClassDetail = {
  id: number;
  name: string;
  description: string | null;
  teachers: ClassMember[];
  students: ClassMember[];
  myRentals: MyClassRental[];
};

export type UserSearchResult = {
  id: number;
  displayName: string;
  email: string;
  role: string;
};
