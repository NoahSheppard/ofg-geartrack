// Idempotent seed script: populates gear_categories and gear with a starter
// catalogue. Safe to re-run — existing categories/gear (matched by name) are
// left untouched. Run with `npm run seed`.

import { db, run, get, initialOperation } from '../src/util/db.js';

const CATEGORIES = [
    { name: 'Cameras',          description: 'DSLR and mirrorless camera bodies' },
    { name: 'Lenses',           description: 'Interchangeable camera lenses' },
    { name: 'Support & Grip',   description: 'Tripods, gimbals and rigging' },
    { name: 'Lighting',         description: 'Studio and on-location lighting' },
    { name: 'Audio',            description: 'Microphones and field recorders' },
    { name: 'Multi-Media',      description: 'General multimedia equipment and accessories' },
    { name: 'Camera Equipment', description: 'Cameras, lenses, microphones and accessories from the department stocktake' },
    { name: 'Various Equipment', description: 'Miscellaneous department equipment' },
];

const IMAGES = {
    camera:   'https://images.unsplash.com/photo-1616423640778-28d1b53229bd?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxkc2xyJTIwY2FtZXJhfGVufDF8fHx8MTc3ODUyNDA2NHww&ixlib=rb-4.1.0&q=80&w=1080',
    lens:     'https://images.unsplash.com/photo-1582994254571-52c62d96ebab?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxjYW1lcmElMjBsZW5zfGVufDF8fHx8MTc3ODUyNDA2NHww&ixlib=rb-4.1.0&q=80&w=1080',
    support:  'https://images.unsplash.com/photo-1546533982-ef53290bca50?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxwaG90b2dyYXBoeSUyMHRyaXBvZHxlbnwxfHx8fDE3Nzg2MzY5MzR8MA&ixlib=rb-4.1.0&q=80&w=1080',
    lighting: 'https://images.unsplash.com/photo-1471341971476-ae15ff5dd4ea?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxzdHVkaW8lMjBsaWdodGluZ3xlbnwxfHx8fDE3Nzg2MzY5MzR8MA&ixlib=rb-4.1.0&q=80&w=1080',
    audio:    'https://images.unsplash.com/photo-1732998486404-0d24f0a5d7cb?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxhdWRpbyUyMHJlY29yZGVyJTIwem9vbXxlbnwxfHx8fDE3Nzg2MzY5MzR8MA&ixlib=rb-4.1.0&q=80&w=1080',
};

const GEAR = [
    {
        name: 'Canon EOS 5D Mark IV',
        category: 'Cameras',
        description: 'Professional DSLR camera with 30.4 MP full-frame CMOS sensor. Perfect for advanced multimedia projects.',
        quantityTotal: 5,
        condition: 'Good',
        imageUrl: IMAGES.camera,
    },
    {
        name: 'Sony A7 III',
        category: 'Cameras',
        description: 'Full-frame mirrorless camera with fast autofocus and excellent low-light performance.',
        quantityTotal: 3,
        condition: 'Good',
        imageUrl: IMAGES.camera,
    },
    {
        name: 'Canon EF 24-70mm f/2.8L',
        category: 'Lenses',
        description: 'Standard zoom lens with excellent image quality and a fast f/2.8 max aperture.',
        quantityTotal: 3,
        condition: 'Good',
        imageUrl: IMAGES.lens,
    },
    {
        name: 'Sigma 50mm f/1.4 Art',
        category: 'Lenses',
        description: 'Sharp prime lens with a wide aperture, ideal for portraits and low-light shooting.',
        quantityTotal: 4,
        condition: 'Excellent',
        imageUrl: IMAGES.lens,
    },
    {
        name: 'Manfrotto 190XPRO Tripod',
        category: 'Support & Grip',
        description: 'Sturdy aluminum 3-section tripod with 90-degree center column mechanism.',
        quantityTotal: 10,
        condition: 'Good',
        imageUrl: IMAGES.support,
    },
    {
        name: 'DJI Ronin-S Gimbal',
        category: 'Support & Grip',
        description: '3-axis handheld gimbal stabiliser for smooth motion footage with DSLR/mirrorless cameras.',
        quantityTotal: 2,
        condition: 'Good',
        imageUrl: IMAGES.support,
    },
    {
        name: 'Aputure 120D II Studio Light',
        category: 'Lighting',
        description: 'Daylight-balanced LED video light. Very bright and accurate colour rendition.',
        quantityTotal: 4,
        condition: 'Good',
        imageUrl: IMAGES.lighting,
    },
    {
        name: 'Neewer Softbox Kit',
        category: 'Lighting',
        description: 'Two-light softbox lighting kit with stands, ideal for interviews and product shoots.',
        quantityTotal: 6,
        condition: 'Fair',
        imageUrl: IMAGES.lighting,
    },
    {
        name: 'Zoom H6 Audio Recorder',
        category: 'Audio',
        description: 'Handy portable recorder with interchangeable microphone capsules.',
        quantityTotal: 2,
        condition: 'Good',
        imageUrl: IMAGES.audio,
    },
    {
        name: 'Rode Wireless GO II',
        category: 'Audio',
        description: 'Compact dual-channel wireless microphone system for interviews and run-and-gun video.',
        quantityTotal: 5,
        condition: 'Excellent',
        imageUrl: IMAGES.audio,
    },

    // ─── Department stocktake: Multi-Media ─────────────────────────────────
    {
        name: 'Go-Pro',
        category: 'Multi-Media',
        manufacturer: 'SP',
        description: 'POV Case Padded Kit (Bag 9)',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Tripod Umbrella',
        category: 'Multi-Media',
        manufacturer: 'LightPro',
        quantityTotal: 2,
        condition: 'Good',
    },
    {
        name: 'Tripods',
        category: 'Multi-Media',
        quantityTotal: 10,
        condition: 'Good',
    },
    {
        name: 'Electrical (Cords & Clamps)',
        category: 'Multi-Media',
        type: 'Cords & Clamps',
        description: 'Various',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Sound Recorders',
        category: 'Multi-Media',
        manufacturer: 'Zoom Sound Lab',
        serialNo: 'R91402P, R91401N (OFG Reg. Nos.)',
        quantityTotal: 2,
        condition: 'Good',
    },
    {
        name: 'Tech Glasses',
        category: 'Multi-Media',
        manufacturer: 'Sony',
        quantityTotal: 3,
        condition: 'Good',
    },
    {
        name: 'Graphics Tablet (Bamboo)',
        category: 'Multi-Media',
        manufacturer: 'Wacom',
        modelNo: 'CTH-670',
        type: 'Pen & Touch Tablet',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Stick Light',
        category: 'Multi-Media',
        manufacturer: 'Neewer',
        type: 'Stick Light',
        description: 'Handheld stick light (rose gold)',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Mobile Phone Holder',
        category: 'Multi-Media',
        manufacturer: 'Firefly Maxxum',
        quantityTotal: 5,
        condition: 'Good',
    },
    {
        name: 'USB-C Adaptor',
        category: 'Multi-Media',
        manufacturer: 'Keji',
        description: '2 pack',
        quantityTotal: 2,
        condition: 'Good',
    },
    {
        name: 'Security Screws for PC',
        category: 'Multi-Media',
        manufacturer: 'Lindy.com',
        description: '1 zip-lock bag',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Cords/Chargers etc.',
        category: 'Multi-Media',
        description: 'PC/laptop chargers & cords etc.',
        quantityTotal: 1,
        condition: 'Loose',
    },
    {
        name: 'Drones',
        category: 'Multi-Media',
        manufacturer: 'Airblock',
        description: 'Kept in large boxes in white cupboard',
        quantityTotal: 6,
        condition: 'Good',
    },

    // ─── Department stocktake: Camera Equipment ────────────────────────────
    {
        name: 'Canon EOS 600D + Lens',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        serialNo: 'R91396F (OFG)',
        type: 'Digital Camera',
        description: "Marked 'one' — battery 'one' inside camera",
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Canon EOS 90D + Lens',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        serialNo: 'R91404W (OFG)',
        type: 'Digital Camera',
        description: "Marked 'two' — battery inside camera",
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Canon EOS 70D + Lens',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        serialNo: 'R91392L (OFG)',
        type: 'Digital Camera',
        description: "Marked 'three' — battery & charger cords",
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Canon EOS 450D + Lens',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        serialNo: 'R91395P (OFG)',
        type: 'Digital Camera',
        description: "Marked 'five' — battery inside & power cord",
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Canon EOS R50 + Lens',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        serialNo: 'R93089W (OFG)',
        type: 'Digital Camera',
        description: 'Unmarked — battery inside & power cord',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Chargers/Batteries (Canon)',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        description: 'Stored in zip-lock bag',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Canon 50mm Lens (Spare)',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        type: 'Lens',
        description: 'Loose spare 50mm lens',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Lens Caps',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        description: 'Various sizes',
        quantityTotal: 10,
        condition: 'Good',
    },
    {
        name: 'Camera Straps',
        category: 'Camera Equipment',
        manufacturer: 'Canon',
        description: 'Various sizes',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Camera Manuals',
        category: 'Camera Equipment',
        description: 'Various brands',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'On-Camera Microphone (Rode)',
        category: 'Camera Equipment',
        manufacturer: 'Rode Microphone',
        serialNo: 'R91408J, R91407A, R91409K (OFG)',
        quantityTotal: 3,
        condition: 'Good',
    },
    {
        name: 'Small Microphone (Rode)',
        category: 'Camera Equipment',
        manufacturer: 'Rode Microphone',
        serialNo: 'R91398X, R91397W (OFG)',
        quantityTotal: 2,
        condition: 'Good',
    },
    {
        name: '3/4" Condenser Microphone (Rode)',
        category: 'Camera Equipment',
        manufacturer: 'Rode Microphone',
        serialNo: 'R91411P, R91410N (OFG)',
        quantityTotal: 2,
        condition: 'Good',
    },
    {
        name: 'Olympus Lens',
        category: 'Camera Equipment',
        manufacturer: 'Olympus',
        type: 'Lens',
        serialNo: 'R91414X, R91413W (OFG)',
        quantityTotal: 2,
        condition: 'Good',
    },
    {
        name: 'Wireless Audio System (Rode Link)',
        category: 'Camera Equipment',
        manufacturer: 'Rode',
        modelNo: 'Rode Link',
        serialNo: 'R91412F (OFG)',
        description: 'Filmmaker equipment',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Samsung Gear 360',
        category: 'Camera Equipment',
        manufacturer: 'Samsung',
        serialNo: 'R91403F (OFG)',
        type: '360° Camera',
        description: 'Live broadcast high-resolution equipment',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Camera Filter (Hoya No.8, 58mm)',
        category: 'Camera Equipment',
        manufacturer: 'Hoya',
        serialNo: 'R91405X (OFG)',
        type: 'Camera Filter',
        description: 'No.8 filter, 58mm',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Quick Release Plate (DJI RS Mini)',
        category: 'Camera Equipment',
        manufacturer: 'DJI',
        modelNo: 'RS Mini',
        type: 'Quick Release Plate',
        description: 'Includes screw kit',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'SD Card (SanDisk 64GB)',
        category: 'Camera Equipment',
        manufacturer: 'SanDisk',
        type: 'Memory Card',
        description: '64GB, loose',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'USB Wall Charger & Cord',
        category: 'Camera Equipment',
        type: 'Charger',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Graphics Tablet (Wacom, TAS series)',
        category: 'Camera Equipment',
        manufacturer: 'Wacom',
        type: 'Graphics Tablet',
        serialNo: 'R93462L, R93466F, R93460J, R93470K, R93464N, R93459X, R93457F, R93465P, R93467W, R93472M, R93469Y, R93463M, R93461K, R93468X, R93458W, R93471L (OFG, TAS 1-16)',
        quantityTotal: 16,
        condition: 'Good',
    },
    {
        name: 'Go-Pro Parts (Spares Case)',
        category: 'Camera Equipment',
        serialNo: 'R92268P (OFG)',
        description: 'Black padded case holding spare parts',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'RONIN Equipment Case',
        category: 'Camera Equipment',
        manufacturer: 'RONIN',
        serialNo: 'R91423X (OFG)',
        description: 'Large black padded suitcase',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'SD Cards (Assorted)',
        category: 'Camera Equipment',
        type: 'Memory Card',
        description: 'Small plastic container with various cards',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Mouse & Cords',
        category: 'Camera Equipment',
        description: 'Various, stored in grey plastic box',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Network Cables',
        category: 'Camera Equipment',
        description: 'Kit 1 & Kit 8 — boxes of black cables',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Cables Box',
        category: 'Camera Equipment',
        description: 'Blue cable cords',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: 'Coat Hanger & Clothes Rack',
        category: 'Camera Equipment',
        quantityTotal: 1,
        condition: 'Good',
    },

    // ─── Department stocktake: Various Equipment ───────────────────────────
    {
        name: 'Green/Black/White Screen',
        category: 'Various Equipment',
        type: 'Backdrop Screen',
        description: 'Various',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: "Sparkfun RedBoard Inventor's Kit",
        category: 'Various Equipment',
        manufacturer: 'Sparkfun Electronics',
        description: "RedBoard circuit board inventor's kits, in cases — kept in white cupboard",
        quantityTotal: 16,
        condition: 'Good',
    },
    {
        name: 'Electrical Boards & Cords',
        category: 'Various Equipment',
        quantityTotal: 1,
        condition: 'Good',
    },
    {
        name: "Sparkfun Inventor's Kit (Unopened)",
        category: 'Various Equipment',
        manufacturer: 'Sparkfun',
        description: 'Various colours — in zip-lock, unopened',
        quantityTotal: 1,
        condition: 'New',
    },
];

async function seed() {
    await initialOperation();

    for (const cat of CATEGORIES) {
        await run(db, `INSERT OR IGNORE INTO gear_categories (name, description) VALUES (?, ?)`, [cat.name, cat.description]);
    }

    for (const item of GEAR) {
        const existing = await get(db, `SELECT gear_id FROM gear WHERE name = ?`, [item.name]);
        if (existing) continue;

        const category = await get(db, `SELECT category_id FROM gear_categories WHERE name = ?`, [item.category]);

        await run(db, `
            INSERT INTO gear (
                category_id, name, description, quantity_total, quantity_available, condition, image_url,
                manufacturer, model_no, serial_no, type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            category.category_id, item.name, item.description ?? null, item.quantityTotal, item.quantityTotal,
            item.condition, item.imageUrl ?? null, item.manufacturer ?? null, item.modelNo ?? null,
            item.serialNo ?? null, item.type ?? null,
        ]);
    }

    console.log('Seed complete.');
    db.close();
}

seed().catch((err) => {
    console.error('Seed failed:', err);
    process.exit(1);
});
