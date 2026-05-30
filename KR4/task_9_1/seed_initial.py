"""Insert two products after the initial migration (before description column exists)."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "products.db"


def seed_initial_products() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM products")
        if cursor.fetchone()[0] >= 2:
            print("Products already seeded.")
            return

        cursor.executemany(
            "INSERT INTO products (title, price, count) VALUES (?, ?, ?)",
            [
                ("Laptop", 999.99, 10),
                ("Mouse", 29.99, 50),
            ],
        )
        conn.commit()
        print("Seeded 2 products (initial migration).")
    finally:
        conn.close()


if __name__ == "__main__":
    seed_initial_products()
