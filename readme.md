# Sběr dat a měření

| Skript | Popis |
| --- | --- |
| `stahni_prace.py` | Stáhne z repozitáře UK metadata závěrečných prací MFF a uloží je s odkazy na PDF do CSV. |
| `save_pdf_mff.py` | Stáhne PDF závěrečných prací podle seznamu v CSV. |
| `url_scan_pdf.py` | Z PDF získá klikací odkazy a URL z textu, vyčistí je a roztřídí do CSV. |
| `url_http_check.py` | Měří dostupnost URL přes HTTP, klasifikuje výsledky a ukládá je do SQLite. |
| `url_corrections.py` | Navrhuje a eviduje opravy neplatných URL a připravuje opravené adresy k přeměření. |
