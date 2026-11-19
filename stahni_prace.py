import requests
import csv
import time

base_url = "https://dspace.cuni.cz/rest/filtered-items"
dspace_base = "https://dspace.cuni.cz"

collection_uuid = "47ab07b9-72c7-4622-bd4a-17bc5578cae1"

offset = 0
limit = 20
all_items = []

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0"
})

def meta(metadata, name):
    if not isinstance(metadata, list):
        return ""

    for m in metadata:
        if isinstance(m, dict) and m.get("key") == name:
            return m.get("value", "")

    return ""

def najdi_pdf_url(bitstreams):
    if not isinstance(bitstreams, list):
        return ""

    for b in bitstreams:
        if not isinstance(b, dict):
            continue

        if (
            b.get("bundleName") == "ORIGINAL"
            and b.get("description") == "Text práce"
            and b.get("retrieveLink")
        ):
            return dspace_base + b.get("retrieveLink")

    for b in bitstreams:
        if not isinstance(b, dict):
            continue

        name = b.get("name", "")
        if (
            b.get("bundleName") == "ORIGINAL"
            and name.lower().endswith(".pdf")
            and b.get("retrieveLink")
        ):
            return dspace_base + b.get("retrieveLink")

    return ""

while True:
    params = {
        "collSel[]": collection_uuid,
        "limit": limit,
        "offset": offset,
        "expand": "metadata,bitstreams,parentCollection",
        "filters": "is_discoverable"
    }

    print(f"Stahuji offset {offset}...")

    success = False

    for pokus in range(1, 8):
        try:
            response = session.get(base_url, params=params, timeout=180)
            response.raise_for_status()
            raw = response.json()

            if isinstance(raw, dict):
                data = raw.get("items", [])
            elif isinstance(raw, list):
                data = raw
            else:
                data = []

            success = True
            break

        except Exception as e:
            print(f"Pokus {pokus} selhal: {e}")
            time.sleep(45)

    if not success:
        print("Nepodařilo se stáhnout další data. Ukládám, co už mám.")
        break

    if not data:
        print("Žádná další data.")
        break

    print(f"Staženo {len(data)} záznamů")
    all_items.extend(data)

    if len(data) < limit:
        break

    offset += limit
    time.sleep(15)

print(f"\nCelkem staženo objektů: {len(all_items)}")

with open("mff_prace_pdf_url.csv", "w", newline="", encoding="utf-8-sig") as f:
    writer = csv.writer(f)

    writer.writerow([
        "název",
        "autor",
        "datum_obhajoby",
        "obor",
        "typ",
        "handle",
        "pdf_url"
    ])

    for item in all_items:
        if not isinstance(item, dict):
            continue

        metadata = item.get("metadata", [])
        bitstreams = item.get("bitstreams", [])

        writer.writerow([
            meta(metadata, "dc.title"),
            meta(metadata, "dc.contributor.author"),
            meta(metadata, "dcterms.dateAccepted"),
            meta(metadata, "thesis.degree.discipline"),
            meta(metadata, "dc.type"),
            item.get("handle", ""),
            najdi_pdf_url(bitstreams)
        ])

print("\nHotovo.")
print("Soubor byl uložen jako mff_prace_pdf_url.csv")