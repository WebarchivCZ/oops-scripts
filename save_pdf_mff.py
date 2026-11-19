import csv
import os
import re
import time
import requests

csv_file = "mff_prace_pdf_url.csv"
pdf_folder = "pdf_mff"

os.makedirs(pdf_folder, exist_ok=True)

session = requests.Session()

session.headers.update({
    "User-Agent": "Mozilla/5.0"
})

def safe_filename(text):

    text = text or "bez_nazvu"

    text = re.sub(
        r'[\\/*?:"<>|]',
        "_",
        text
    )

    return text[:120]


def stahni_pdf(url, path):

    if not url:
        return "bez_url"

    # už existuje → přeskočit
    if os.path.exists(path):

        if os.path.getsize(path) > 0:
            return "existuje"

    for pokus in range(1, 6):

        try:

            response = session.get(
                url,
                timeout=300,
                stream=True
            )

            response.raise_for_status()

            with open(path, "wb") as f:

                for chunk in response.iter_content(
                    chunk_size=1024 * 1024
                ):

                    if chunk:
                        f.write(chunk)

            return "ok"

        except Exception as e:

            print(f"PDF pokus {pokus} selhal:")
            print(e)

            try:
                response.close()
            except:
                pass

            print("Čekám 30 sekund...")
            time.sleep(30)

    return "chyba"


with open(
    csv_file,
    newline="",
    encoding="utf-8-sig"
) as f:

    reader = csv.DictReader(f)

    for i, row in enumerate(reader, start=1):

        title = row.get("název", "")
        url = row.get("pdf_url", "")
        handle = row.get("handle", "")

        filename = safe_filename(
            f"{handle}_{title}"
        ) + ".pdf"

        path = os.path.join(
            pdf_folder,
            filename
        )

        print("\n-----------------------------------")
        print(f"[{i}] {filename}")

        stav = stahni_pdf(url, path)

        print(f"Stav: {stav}")

        # rozumný kompromis mezi rychlostí a stabilitou
        print("Čekám 3 sekundy...")
        time.sleep(3)

print("\nHotovo.")
print("PDF jsou ve složce pdf_mff")