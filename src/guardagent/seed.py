"""Build the small, clearly fictional SQLite database the agent queries.

Quillmoor Supply Co. does not exist. Names are generated from short word lists
with a fixed seed, so the database is identical on every run.
"""
from __future__ import annotations

import datetime as dt
import random
import sqlite3
from pathlib import Path

from .paths import DB_PATH

SCHEMA = """
CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    city TEXT NOT NULL,
    country TEXT NOT NULL,
    tier TEXT NOT NULL CHECK (tier IN ('Bronze', 'Silver', 'Gold')),
    joined_on TEXT NOT NULL
);
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    sku TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    unit_price REAL NOT NULL,
    stock INTEGER NOT NULL
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    ordered_on TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('processing', 'shipped', 'delivered', 'cancelled', 'returned'))
);
CREATE TABLE order_items (
    order_id INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    qty INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    PRIMARY KEY (order_id, product_id)
);
"""

FIRST = ["Ari", "Bex", "Cato", "Dara", "Emrys", "Fen", "Gale", "Hollis", "Ines", "Jory",
         "Kestrel", "Lio", "Mira", "Nils", "Orla", "Pim", "Quin", "Rhea", "Sol", "Tamsin"]
LAST = ["Ashdown", "Brackwater", "Coldharbour", "Dunmere", "Elmsworth", "Farrow", "Greywell",
        "Hartfell", "Ivybridge", "Juniper", "Kettleby", "Lowmoor", "Marrick", "Northcote"]
CITIES = [("Portland", "US"), ("Denver", "US"), ("Boise", "US"), ("Asheville", "US"),
          ("Calgary", "CA"), ("Halifax", "CA"), ("Leeds", "GB"), ("Inverness", "GB")]
PRODUCTS = [
    ("Tents", "Ridgeline 2P Tent", 289.00), ("Tents", "Ridgeline 4P Tent", 419.00),
    ("Tents", "Featherlite Solo Tent", 199.00), ("Tents", "Basecamp 6P Tent", 549.00),
    ("Backpacks", "Trailhead 28L Daypack", 89.00), ("Backpacks", "Summit 55L Pack", 219.00),
    ("Backpacks", "Ultralight 40L Pack", 179.00), ("Backpacks", "Kids 15L Pack", 45.00),
    ("Sleeping bags", "Ember -5C Bag", 239.00), ("Sleeping bags", "Breeze 10C Bag", 99.00),
    ("Sleeping bags", "Down 0C Quilt", 269.00),
    ("Stoves", "Pocket Gas Stove", 49.00), ("Stoves", "Twin Burner Stove", 139.00),
    ("Stoves", "Wood Gasifier Stove", 119.00),
    ("Lanterns", "Glowcap Lantern", 34.00), ("Lanterns", "Solar Hub Lantern", 59.00),
    ("Apparel", "Stormshell Jacket", 199.00), ("Apparel", "Merino Base Layer", 79.00),
    ("Apparel", "Trail Socks 3-pack", 24.00), ("Apparel", "Fleece Midlayer", 89.00),
    ("Apparel", "Rain Pants", 69.00), ("Accessories", "Titanium Spork", 12.00),
    ("Accessories", "Water Filter Straw", 29.00), ("Accessories", "Headlamp 400lm", 39.00),
    ("Accessories", "Trekking Poles Pair", 99.00),
]
STATUSES = ["processing", "shipped", "delivered", "delivered", "delivered", "cancelled", "returned"]


def build(path: Path = DB_PATH, seed: int = 7) -> Path:
    rng = random.Random(seed)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)

    used = set()
    customers = []
    for cid in range(1, 41):
        while True:
            name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
            if name not in used:
                used.add(name)
                break
        city, country = rng.choice(CITIES)
        tier = rng.choices(["Bronze", "Silver", "Gold"], weights=[5, 3, 2])[0]
        joined = dt.date(2023, 1, 1) + dt.timedelta(days=rng.randrange(0, 900))
        customers.append((cid, name, city, country, tier, joined.isoformat()))
    con.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?)", customers)

    products = []
    for pid, (cat, name, price) in enumerate(PRODUCTS, start=1):
        sku = f"QM-{cat[:3].upper()}-{pid:03d}"
        products.append((pid, sku, name, cat, price, rng.randrange(0, 120)))
    con.executemany("INSERT INTO products VALUES (?,?,?,?,?,?)", products)

    orders, items = [], []
    for oid in range(1, 201):
        cid = rng.randrange(1, 41)
        day = dt.date(2026, 1, 1) + dt.timedelta(days=rng.randrange(0, 300))
        orders.append((oid, cid, day.isoformat(), rng.choice(STATUSES)))
        for pid in rng.sample(range(1, len(PRODUCTS) + 1), rng.randrange(1, 4)):
            qty = rng.choices([1, 2, 3, 12], weights=[12, 5, 2, 1])[0]
            items.append((oid, pid, qty, PRODUCTS[pid - 1][2]))
    con.executemany("INSERT INTO orders VALUES (?,?,?,?)", orders)
    con.executemany("INSERT INTO order_items VALUES (?,?,?,?)", items)
    con.commit()
    con.execute("VACUUM")
    con.close()
    return path


SCHEMA_SUMMARY = (
    "customers(id, name, city, country, tier ['Bronze'|'Silver'|'Gold'], joined_on YYYY-MM-DD); "
    "products(id, sku, name, category, unit_price USD, stock); "
    "orders(id, customer_id -> customers.id, ordered_on YYYY-MM-DD, status "
    "['processing'|'shipped'|'delivered'|'cancelled'|'returned']); "
    "order_items(order_id -> orders.id, product_id -> products.id, qty, unit_price USD)"
)
