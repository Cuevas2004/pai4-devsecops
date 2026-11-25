#!/usr/bin/env python3
"""Crea de forma idempotente el contexto de DefectDojo del proyecto PAI4.

Uso local:
    export DEFECTDOJO_URL=http://localhost:8080
    export DEFECTDOJO_API_KEY=...
    python3 .github/scripts/defectdojo_setup.py

Imprime los IDs necesarios para el workflow:
    DEFECTDOJO_PRODUCT_ID=...
    DEFECTDOJO_ENGAGEMENT_ID=...
"""
import argparse
import os
import sys
from datetime import date

from defectdojo_client import DefectDojoClient, DefectDojoError

PRODUCT_TYPE = "Aplicaciones Web"
PRODUCT = "OWASP Juice Shop - PAI4"
ENGAGEMENT = "CI/CD DevSecOps - main"


def find_one(client, path, **criteria):
    data = client.get(path, {"limit": 200})
    for item in data.get("results", []):
        if all(item.get(key) == value for key, value in criteria.items()):
            return item
    return None


def find_or_create(client, path, criteria, payload, label):
    item = find_one(client, path, **criteria)
    if item:
        print(f"{label}: ya existe id={item['id']}")
        return item
    item = client.post(path, payload)
    print(f"{label}: creado id={item['id']}")
    return item


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.getenv("DEFECTDOJO_URL", "http://localhost:8080"))
    parser.add_argument("--api-key", default=os.getenv("DEFECTDOJO_API_KEY"))
    parser.add_argument("--product-type", default=PRODUCT_TYPE)
    parser.add_argument("--product", default=PRODUCT)
    parser.add_argument("--engagement", default=ENGAGEMENT)
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Falta DEFECTDOJO_API_KEY (o --api-key)")

    client = DefectDojoClient(args.url, args.api_key)

    product_type = find_or_create(
        client,
        "/api/v2/product_types/",
        {"name": args.product_type},
        {
            "name": args.product_type,
            "description": "Aplicaciones web analizadas por el pipeline DevSecOps",
            "critical_product": False,
        },
        "Product type",
    )

    product = find_or_create(
        client,
        "/api/v2/products/",
        {"name": args.product, "prod_type": product_type["id"]},
        {
            "name": args.product,
            "description": "Aplicacion web intencionadamente vulnerable usada como SUT en el pipeline DevSecOps.",
            "prod_type": product_type["id"],
            "business_criticality": "high",
            "platform": "web",
        },
        "Producto",
    )

    engagement = find_or_create(
        client,
        "/api/v2/engagements/",
        {"name": args.engagement, "product": product["id"]},
        {
            "name": args.engagement,
            "description": "Importacion automatica de los informes SAST, SCA y DAST generados por GitHub Actions.",
            "product": product["id"],
            "target_start": date.today().isoformat(),
            "target_end": "2027-06-30",
            "status": "In Progress",
            "engagement_type": "CI/CD",
            "deduplication_on_engagement": True,
        },
        "Engagement",
    )

    print(f"DEFECTDOJO_PRODUCT_TYPE_ID={product_type['id']}")
    print(f"DEFECTDOJO_PRODUCT_ID={product['id']}")
    print(f"DEFECTDOJO_ENGAGEMENT_ID={engagement['id']}")


if __name__ == "__main__":
    try:
        main()
    except DefectDojoError as error:
        sys.exit(f"ERROR DefectDojo: {error}")
