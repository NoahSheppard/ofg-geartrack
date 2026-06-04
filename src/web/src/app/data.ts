export const MOCK_GEAR = [
  {
    id: "g1",
    name: "Canon EOS 5D Mark IV",
    category: "Camera",
    description: "Professional DSLR camera with 30.4 MP full-frame CMOS sensor. Perfect for advanced multimedia projects.",
    photo: "https://images.unsplash.com/photo-1616423640778-28d1b53229bd?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxkc2xyJTIwY2FtZXJhfGVufDF8fHx8MTc3ODUyNDA2NHww&ixlib=rb-4.1.0&q=80&w=1080",
    stock: 5,
    maxRentDays: 7,
  },
  {
    id: "g2",
    name: "Canon EF 24-70mm f/2.8L",
    category: "Lens",
    description: "Standard zoom lens with excellent image quality and a fast f/2.8 max aperture.",
    photo: "https://images.unsplash.com/photo-1582994254571-52c62d96ebab?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxjYW1lcmElMjBsZW5zfGVufDF8fHx8MTc3ODUyNDA2NHww&ixlib=rb-4.1.0&q=80&w=1080",
    stock: 3,
    maxRentDays: 7,
  },
  {
    id: "g3",
    name: "Manfrotto 190XPRO Tripod",
    category: "Support",
    description: "Sturdy aluminum 3-section tripod with 90-degree center column mechanism.",
    photo: "https://images.unsplash.com/photo-1546533982-ef53290bca50?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxwaG90b2dyYXBoeSUyMHRyaXBvZHxlbnwxfHx8fDE3Nzg2MzY5MzR8MA&ixlib=rb-4.1.0&q=80&w=1080",
    stock: 10,
    maxRentDays: 14,
  },
  {
    id: "g4",
    name: "Aputure 120D II Studio Light",
    category: "Lighting",
    description: "Daylight-balanced LED video light. Very bright and accurate color rendition.",
    photo: "https://images.unsplash.com/photo-1471341971476-ae15ff5dd4ea?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxzdHVkaW8lMjBsaWdodGluZ3xlbnwxfHx8fDE3Nzg2MzY5MzR8MA&ixlib=rb-4.1.0&q=80&w=1080",
    stock: 4,
    maxRentDays: 5,
  },
  {
    id: "g5",
    name: "Zoom H6 Audio Recorder",
    category: "Audio",
    description: "Handy portable recorder with interchangeable microphone capsules.",
    photo: "https://images.unsplash.com/photo-1732998486404-0d24f0a5d7cb?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxhdWRpbyUyMHJlY29yZGVyJTIwem9vbXxlbnwxfHx8fDE3Nzg2MzY5MzR8MA&ixlib=rb-4.1.0&q=80&w=1080",
    stock: 2,
    maxRentDays: 7,
  }
];

export const MOCK_GEAR_UNITS = [
  // Canon EOS 5D x5
  { id: "g1-u1", gearId: "g1", label: "Body #1" },
  { id: "g1-u2", gearId: "g1", label: "Body #2" },
  { id: "g1-u3", gearId: "g1", label: "Body #3" },
  { id: "g1-u4", gearId: "g1", label: "Body #4" },
  { id: "g1-u5", gearId: "g1", label: "Body #5" },
  // Canon 24-70mm x3
  { id: "g2-u1", gearId: "g2", label: "Lens #1" },
  { id: "g2-u2", gearId: "g2", label: "Lens #2" },
  { id: "g2-u3", gearId: "g2", label: "Lens #3" },
  // Manfrotto Tripod x10
  { id: "g3-u1", gearId: "g3", label: "Tripod #1" },
  { id: "g3-u2", gearId: "g3", label: "Tripod #2" },
  { id: "g3-u3", gearId: "g3", label: "Tripod #3" },
  { id: "g3-u4", gearId: "g3", label: "Tripod #4" },
  { id: "g3-u5", gearId: "g3", label: "Tripod #5" },
  { id: "g3-u6", gearId: "g3", label: "Tripod #6" },
  { id: "g3-u7", gearId: "g3", label: "Tripod #7" },
  { id: "g3-u8", gearId: "g3", label: "Tripod #8" },
  { id: "g3-u9", gearId: "g3", label: "Tripod #9" },
  { id: "g3-u10", gearId: "g3", label: "Tripod #10" },
  // Aputure Light x4
  { id: "g4-u1", gearId: "g4", label: "Light #1" },
  { id: "g4-u2", gearId: "g4", label: "Light #2" },
  { id: "g4-u3", gearId: "g4", label: "Light #3" },
  { id: "g4-u4", gearId: "g4", label: "Light #4" },
  // Zoom H6 x2
  { id: "g5-u1", gearId: "g5", label: "Recorder #1" },
  { id: "g5-u2", gearId: "g5", label: "Recorder #2" },
];

export const MOCK_STUDENTS = [
  { id: "s1", name: "Alex Johnson", email: "alex.j@hs.edu" },
  { id: "s2", name: "Maria Garcia", email: "maria.g@hs.edu" },
  { id: "s3", name: "Sam Smith", email: "sam.s@hs.edu" },
  { id: "s4", name: "Jordan Lee", email: "jordan.l@hs.edu" },
  { id: "s5", name: "Priya Patel", email: "priya.p@hs.edu" },
];

export const MOCK_CLASSES = [
  { id: "c1", name: "Intro to Multimedia", students: ["s1", "s2", "s4"] },
  { id: "c2", name: "Advanced Filmmaking", students: ["s1", "s3", "s5"] },
  { id: "c3", name: "Audio Production", students: ["s2", "s3", "s4", "s5"] },
];

export const MOCK_RENTALS = [
  // Alex has cameras + tripod
  { id: "r1", studentId: "s1", gearId: "g1", unitId: "g1-u1", status: "Active",  dueDate: "2026-05-20", checkoutDate: "2026-05-13" },
  { id: "r2", studentId: "s1", gearId: "g3", unitId: "g3-u1", status: "Active",  dueDate: "2026-05-25", checkoutDate: "2026-05-11" },
  // Maria has recorder (overdue) + lens
  { id: "r3", studentId: "s2", gearId: "g5", unitId: "g5-u1", status: "Overdue", dueDate: "2026-05-05", checkoutDate: "2026-04-28" },
  { id: "r4", studentId: "s2", gearId: "g2", unitId: "g2-u1", status: "Active",  dueDate: "2026-05-18", checkoutDate: "2026-05-11" },
  // Sam has camera (overdue) + light
  { id: "r5", studentId: "s3", gearId: "g1", unitId: "g1-u2", status: "Overdue", dueDate: "2026-05-08", checkoutDate: "2026-05-01" },
  { id: "r6", studentId: "s3", gearId: "g4", unitId: "g4-u1", status: "Active",  dueDate: "2026-05-16", checkoutDate: "2026-05-11" },
  // Jordan has two cameras + lens + tripod
  { id: "r7", studentId: "s4", gearId: "g1", unitId: "g1-u3", status: "Active",  dueDate: "2026-05-22", checkoutDate: "2026-05-15" },
  { id: "r8", studentId: "s4", gearId: "g1", unitId: "g1-u4", status: "Active",  dueDate: "2026-05-22", checkoutDate: "2026-05-15" },
  { id: "r9", studentId: "s4", gearId: "g2", unitId: "g2-u2", status: "Active",  dueDate: "2026-05-19", checkoutDate: "2026-05-12" },
  { id: "r10", studentId: "s4", gearId: "g3", unitId: "g3-u2", status: "Active", dueDate: "2026-05-24", checkoutDate: "2026-05-10" },
  // Priya has recorder + light + lens
  { id: "r11", studentId: "s5", gearId: "g5", unitId: "g5-u2", status: "Active",  dueDate: "2026-05-21", checkoutDate: "2026-05-14" },
  { id: "r12", studentId: "s5", gearId: "g4", unitId: "g4-u2", status: "Active",  dueDate: "2026-05-17", checkoutDate: "2026-05-12" },
  { id: "r13", studentId: "s5", gearId: "g2", unitId: "g2-u3", status: "Overdue", dueDate: "2026-05-09", checkoutDate: "2026-05-02" },
];

export const CURRENT_USER = {
  id: "s1",
  name: "Alex Johnson",
  email: "alex.j@hs.edu",
  role: "student",
};
