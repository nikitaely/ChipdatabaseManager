#!/usr/bin/env python3
import psycopg2


def test_database_connection():
    config = {
        'host': '192.168.7.109',  # IP вашего Windows PC
        'database': 'postgres',
        'user': 'postgres',
        'password': '1111',
        'port': 5432
    }

    try:
        conn = psycopg2.connect(**config)
        print("✅ Connected to PostgreSQL successfully!")
        conn.close()
        return True
    except Exception as e:
        print("❌ Connection failed: ", e)
        return False


if __name__ == "__main__":
    test_database_connection()