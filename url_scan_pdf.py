import fitz
import csv
import os
import time
import re
import ipaddress
from urllib.parse import urlparse

# Ostrý běh nad kompletní sadou PDF.
pdf_folder = "pdf_mff"
# Pro omezený testovací běh použijte:
# pdf_folder = "pdf_mff_test"

output_all = "url_vse.csv"
output_ok = "url_ok.csv"
output_suspicious = "url_podezrele.csv"
output_rejected = "url_odmitnute.csv"

CSV_COLUMNS = [
    "pdf_soubor",
    "strana",
    "typ",
    "url_raw",
    "url_clean",
    "url_navrzena",
    "stav",
    "confidence",
    "duvod"
]

# URL z textu bereme pouze od http:// nebo https://.
# Nebereme www. bez protokolu, protože to dělalo moc falešných nálezů.
URL_START_RE = re.compile(r'https?://', re.IGNORECASE)

# Tvrdý konec URL v textu.
# Mezery a tabulátory vždy URL ukončují.
# Newline sem záměrně nepatří, protože některé URL jsou v PDF zlomené přes řádek.
URL_HARD_END_CHARS = {
    " ",
    "\t",
    "\f",
    "\v",
    "\u00a0"
}

# Znaky, které jsou běžně povolené v URL.
# Používá se hlavně při rozhodování, zda připojit další řádek za newline.
# Znaky < a > zde podporujeme kvůli starším JSTOR SICI a DOI adresám,
# které je používají přímo v identifikátoru, např.:
# 1520-0434(2003)018<0545:NAS>2.0.CO;2
ALLOWED_URL_CHARS_RE = re.compile(
    r"^[A-Za-z0-9/._~:%?#\[\]@!$&'()*+,;=<>-]+$"
)

# Tyto znaky na konci URL bezpečně odstraňujeme.
# Závorky zde úmyslně nejsou, protože dříve bylo domluveno,
# že závorky obecně nemažeme.
TRAILING_SAFE_PUNCTUATION = ".,;\"'\n\r\t "

# Obvyklé přípony souborů.
# U většiny z nich URL ukončíme, pokud za nimi není query string.
# Speciální pravidlo pro .htm a .html je níže zvlášť.
STOP_AFTER_EXTENSIONS = [
    "shtml", "git",
    "pdf", "ps",
    "png", "jpg", "jpeg", "gif", "svg",
    "zip", "rar", "gz", "tar",
    "txt", "csv", "json", "xml",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "php", "asp", "aspx", "jsp"
]

# Oficiální seznam kořenových TLD od IANA.
# Zdroj: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
# Soubor je uložený vedle skriptu, aby kontrola fungovala i bez internetu.
# Při aktualizaci seznamu stačí nahradit tento soubor novou verzí od IANA.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TLD_LIST_PATH = os.path.join(SCRIPT_DIR, "tlds-alpha-by-domain.txt")


def load_valid_tlds(path):
    """Načte lokální oficiální seznam TLD IANA do množiny."""

    try:
        with open(path, "r", encoding="ascii") as file:
            tlds = {
                line.strip().upper()
                for line in file
                if line.strip() and not line.startswith("#")
            }
    except OSError as exc:
        raise RuntimeError(
            f"Nelze načíst seznam TLD IANA: {path}"
        ) from exc

    if not tlds:
        raise RuntimeError(f"Seznam TLD IANA je prázdný: {path}")

    return frozenset(tlds)


VALID_TLDS = load_valid_tlds(TLD_LIST_PATH)


def has_registered_tld(hostname):
    """Ověří poslední část hostname proti kořenovému seznamu IANA."""

    hostname = hostname.rstrip(".")

    if "." not in hostname:
        return False

    tld = hostname.rsplit(".", 1)[-1]

    try:
        # IANA zapisuje mezinárodní TLD v ASCII tvaru XN--... .
        tld_ascii = tld.encode("idna").decode("ascii").upper()
    except UnicodeError:
        return False

    return tld_ascii in VALID_TLDS


def unique_reasons(reasons):
    result = []

    for reason in reasons:
        if reason and reason not in result:
            result.append(reason)

    return "; ".join(result) if result else "bez_poznamky"


def starts_like_url(url):
    lower = url.lower()
    return lower.startswith("http://") or lower.startswith("https://")


def has_valid_domain(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    hostname = parsed.hostname or ""

    if not hostname:
        return False

    # Číselná IPv4 a IPv6 adresa nepotřebuje TLD.
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    return has_registered_tld(hostname)


def get_hostname(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    hostname = parsed.hostname or ""
    return hostname.lower()


def is_github_domain(url):
    hostname = get_hostname(url)

    return (
        hostname == "github.com"
        or hostname.endswith(".github.com")
        or hostname == "github.io"
        or hostname.endswith(".github.io")
    )


def get_next_segment(text, index):
    """
    Vrátí text za newline až do další mezery / tabu / dalšího newline.

    Používá se při rozhodování, jestli zlomenou URL přes řádek spojit,
    nebo ji ukončit.
    """

    segment = []
    i = index

    while i < len(text):
        ch = text[i]

        if ch in URL_HARD_END_CHARS or ch in ["\n", "\r"]:
            break

        segment.append(ch)
        i += 1

    return "".join(segment)


def should_continue_after_newline(current_url, next_segment):
    """
    Rozhoduje, jestli URL pokračuje za novým řádkem.

    Pravidla:
    - další řádek nesmí začínat novou URL, ani URL za číslem poznámky
    - celý další segment musí obsahovat jen URL-safe znaky
    - ISSN/copyright řádky typu 0003-2670/© nepřipojujeme
    - samotné číslo ani bibliografický rok za newline nepřipojujeme
    - po tečce pokračujeme jen u rozdělené domény, známé přípony souboru
      nebo pokud další segment obsahuje jiné znaky typické pro URL
    - pokračujeme jen tehdy, když to opravdu vypadá jako pokračování URL
    """

    if not next_segment:
        return False

    # Nová URL může být uvedená přímo nebo za číslem poznámky pod čarou,
    # např. "3https://github.com/...". V obou případech aktuální URL končí.
    if re.match(r'^\d*https?://', next_segment, flags=re.IGNORECASE):
        return False

    # Pokud další segment obsahuje znak, který nemůže být v URL,
    # celý segment nepřipojujeme.
    # Tím se řeší např. znak ©.
    if not ALLOWED_URL_CHARS_RE.fullmatch(next_segment):
        return False

    # Bibliografické řádky za DOI často začínají ISSN:
    # 0003-2670/...
    # 0925-4005/...
    # To nechceme připojit k URL.
    if re.match(r'^\d{4}-\d{3}[\dXx](?:/|$)', next_segment):
        return False

    # Samotné číslo na dalším řádku bývá poznámka / číslo stránky.
    if re.fullmatch(r'\d+', next_segment):
        return False

    # Bibliografický rok za URL není její součást.
    # Např. https://github.com/Microsoft/CNTK. + newline + (2016).
    if re.fullmatch(r'\(\d{4}\)[.,;:]?', next_segment):
        return False

    # Jasné pokračování URL.
    previous_char = current_url[-1] if current_url else ""

    if previous_char in "-_/%#?=&":
        return True

    if previous_char == ".":
        parsed = urlparse(current_url)

        # Rozdělená doména, např. http://doi.wiley. + newline + com/...
        # Spojenou doménu přijmeme jen tehdy, když její poslední část je
        # registrovaná TLD ze seznamu IANA. Tím odmítneme např. bibliografii:
        # http://odkaz. + newline + Zou, H. ...
        if (
            parsed.hostname
            and parsed.hostname.endswith(".")
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        ):
            hostname_match = re.match(r'^[A-Za-z0-9.-]+', next_segment)

            if not hostname_match:
                return False

            combined_hostname = parsed.hostname + hostname_match.group(0)
            return has_registered_tld(combined_hostname)

        # Rozdělená známá přípona, např. index. + newline + html.
        extension_pattern = "|".join(
            re.escape(ext)
            for ext in ["htm", "html"] + STOP_AFTER_EXTENSIONS
        )

        if re.match(
            rf'^(?:{extension_pattern})(?:$|[/?#])',
            next_segment,
            flags=re.IGNORECASE
        ):
            return True

    # Další segment obsahuje znaky typické pro URL.
    if re.search(r'[/.?=&_%#-]', next_segment):
        return True

    return False


def extract_http_urls_from_text(text):
    """
    Najde URL v textu stránky PDF.

    Důležité pravidlo:
    - v jedné URL dovolíme maximálně jeden newline
    - jakmile by se URL měla lámat přes druhý newline, ukončíme ji
    """

    results = []

    for match in URL_START_RE.finditer(text):
        i = match.start()

        raw_chars = []
        clean_chars = []

        newline_count = 0
        has_joined_newline = False

        while i < len(text):
            ch = text[i]

            if ch in URL_HARD_END_CHARS:
                break

            if ch in ["\r", "\n"]:

                # Pravidlo: jedna URL může obsahovat maximálně jeden newline.
                # Pokud narazíme na druhý newline, bereme to jako konec URL.
                if newline_count >= 1:
                    break

                newline_count += 1
                raw_chars.append(ch)

                # CRLF ošetření pro Windows konce řádků.
                if ch == "\r" and i + 1 < len(text) and text[i + 1] == "\n":
                    i += 1
                    raw_chars.append("\n")

                next_index = i + 1
                next_segment = get_next_segment(text, next_index)

                current_url = "".join(clean_chars)

                if not should_continue_after_newline(current_url, next_segment):
                    break

                # Pokud newline opravdu bereme jako zlomenou URL,
                # v čisté URL newline odstraníme.
                has_joined_newline = True
                i += 1
                continue

            raw_chars.append(ch)
            clean_chars.append(ch)
            i += 1

        raw_url = "".join(raw_chars)
        clean_candidate = "".join(clean_chars)

        if not clean_candidate:
            continue

        source_type = "text_pres_newline" if has_joined_newline else "text"

        results.append({
            "source_type": source_type,
            "url_raw": raw_url,
            "url_for_cleaning": clean_candidate
        })

    return results


def cut_after_html_extension(url):
    """
    Speciální pravidlo:
    Jakmile je v cestě URL .htm nebo .html, URL tam končí.

    Příponu hledáme pouze v path, nikdy v doméně. Stejnou zásadu používá
    i obecné pravidlo níže, aby např. doména www.json.org nebyla považována
    za soubor s příponou .json.

    Dříve jsme u přípon povolovali pokračování přes ?query=...
    Nově pro .htm a .html platí tvrdší pravidlo:
    .htm i .html vždy ukončí URL.
    """

    parsed = urlparse(url)
    path = parsed.path
    match = re.search(r'\.(?:html|htm)', path, flags=re.IGNORECASE)

    if match:
        path_start = len(parsed.scheme) + 3 + len(parsed.netloc)
        absolute_end = path_start + match.end()
        return url[:absolute_end], "ukonceno_za_html_nebo_htm"

    return url, ""


def cut_after_known_extension(url):
    """
    Obecné pravidlo pro souborové přípony.

    Pokud cesta URL obsahuje jasnou souborovou příponu, např. .pdf nebo
    .zip, URL po ní ukončíme. Hostname se nekontroluje: v doméně
    https://www.json.org/ je .json část názvu domény, nikoliv přípona.

    Výjimka:
    Pokud za příponou následuje ?, považujeme to za query string
    a URL necháme pokračovat.

    Pozor:
    .htm a .html se řeší zvlášť tvrdším pravidlem výše.
    """

    parsed = urlparse(url)
    path = parsed.path

    if not path:
        return url, ""

    path_start = len(parsed.scheme) + 3 + len(parsed.netloc)

    for ext in STOP_AFTER_EXTENSIONS:
        pattern = re.compile(
            rf'(\.{re.escape(ext)})(?=[^A-Za-z0-9]|$)',
            re.IGNORECASE
        )

        match = pattern.search(path)

        if match:
            next_char_index = match.end(1)

            # Pokud po příponě následuje ?, URL pokračuje query stringem.
            # urlparse odděluje query od path, takže zde kontrolujeme,
            # zda přípona ukončuje path a URL současně obsahuje query.
            if next_char_index == len(path) and parsed.query:
                continue

            absolute_end = path_start + match.end(1)
            return url[:absolute_end], f"ukonceno_za_priponou_{ext}"

    return url, ""


def clean_github_url(url):
    """
    Speciální pravidlo pro GitHub.

    Důvody:
    - GitHub URL často obsahují tečky, pomlčky, podtržítka, velká písmena
      a cesty k souborům.
    - Nechceme je zbytečně označovat jako podezřelé.
    - Pokud ale najdeme samostatnou koncovku cesty .git, ukončíme URL za ní.
    - Řetězec ".git" uvnitř domény github.io se nesmí považovat za koncovku.
    """

    if not is_github_domain(url):
        return url, ""

    match = re.search(r'\.git(?=$|[/?#])', url, flags=re.IGNORECASE)

    if match:
        return url[:match.end()], "github_ukonceno_za_git"

    return url, ""


def looks_like_doi_url(url):
    """
    DOI poznáme hlavně podle tvaru 10.xxxx/něco.

    Toto funguje nejen pro doi.org a dx.doi.org,
    ale i pro vydavatelské DOI domény jako doi.wiley.com.
    """

    return re.search(r'(?:^|/)10\.\d{4,9}/', url) is not None


def trim_doi_url(url):
    """
    Vylepšené DOI pravidlo.

    Problém:
    V bibliografii se za DOI někdy nalepí autor nebo text, např.

    http://doi.wiley.com/10.1002/qj.2982.Belo-Pereira

    Správně má zůstat:

    http://doi.wiley.com/10.1002/qj.2982

    Konzervativní řešení:
    - pravidlo použijeme jen pokud URL obsahuje DOI tvar 10.xxxx/
    - odřízneme pouze finální nalepený autorský suffix typu:
      .Belo
      .Belo-Pereira
      .Novak
    - nepoužíváme globální pravidlo "všechno po poslední tečce pryč",
      protože to by rozbilo běžné URL i legitimní DOI.
    """

    if not looks_like_doi_url(url):
        return url, ""

    # Query string a fragment necháváme stranou.
    # DOI trimming děláme jen na hlavní části URL.
    split_match = re.search(r'[?#]', url)

    if split_match:
        main_part = url[:split_match.start()]
        rest = url[split_match.start():]
    else:
        main_part = url
        rest = ""

    # Case-sensitive regex:
    # Důležité je NEPOUŽÍT re.IGNORECASE,
    # protože jinak by se mohly chybně řezat části DOI jako .snb nebo .aca.
    author_suffix_re = re.compile(
        r'\.[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]'
        r'[A-Za-zÁČĎÉĚÍŇÓŘŠŤÚŮÝŽáčďéěíňóřšťúůýž]+'
        r'(?:-[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]'
        r'[A-Za-zÁČĎÉĚÍŇÓŘŠŤÚŮÝŽáčďéěíňóřšťúůýž]+)*$'
    )

    match = author_suffix_re.search(main_part)

    if match:
        return main_part[:match.start()] + rest, "ukonceno_po_doi_pred_autorem"

    return url, ""


def basic_clean_url(url):
    """
    Základní čištění URL.

    Tady se dělají automatické opravy, které považujeme za dost bezpečné.
    Podezřelé, ale ne zcela jisté případy řeší až suggest_clean_url().
    """

    reasons = []

    if not url:
        return "", ["prazdna_hodnota"]

    original = url
    url = url.strip()

    if url != original:
        reasons.append("strip_whitespace")

    # Pokud se před http/https nalepil nějaký text, odřízneme ho.
    match = re.search(r'https?://', url, flags=re.IGNORECASE)

    if match and match.start() > 0:
        url = url[match.start():]
        reasons.append("odstranen_prefix_pred_http")

    # Bezpečné odstranění běžné interpunkce z konce.
    before = url
    url = url.rstrip(TRAILING_SAFE_PUNCTUATION)

    if url != before:
        reasons.append("odstranena_koncova_interpunkce")

    # Za lomítkem na konci nenechat závorku.
    # Např. https://example.com/) -> https://example.com/
    before = url
    url = re.sub(r'/[\)\]\}]$', '/', url)

    if url != before:
        reasons.append("odstranena_zavorka_za_lomitkem")

    # Pokud je přímo za lomítkem tečka nebo čárka,
    # bereme to jako konec odkazu.
    # Např. https://example.com/.Text -> https://example.com/
    before = url
    url = re.sub(r'/[.,].*$', '/', url)

    if url != before:
        reasons.append("ukonceno_pred_teckou_nebo_carkou_za_lomitkem")

    # Pokud URL končí jako "/.", opravíme na "/".
    before = url
    url = re.sub(r'/[.]+$', '/', url)

    if url != before:
        reasons.append("oprava_lomitko_tecka_na_konci")

    # Speciální pravidlo pro GitHub.
    before = url
    url, github_reason = clean_github_url(url)

    if url != before and github_reason:
        reasons.append(github_reason)

    # Tvrdé pravidlo pro .htm a .html:
    # jakmile je v URL .htm nebo .html, URL tam končí.
    before = url
    url, html_reason = cut_after_html_extension(url)

    if url != before and html_reason:
        reasons.append(html_reason)

    # Obecné přípony jako .pdf, .zip, .png...
    # Pokud za nimi není ?, ukončíme URL po příponě.
    before = url
    url, ext_reason = cut_after_known_extension(url)

    if url != before and ext_reason:
        reasons.append(ext_reason)

    # Vylepšené DOI pravidlo:
    # odříznout nalepeného autora/text za DOI,
    # ale jen v konzervativních případech.
    before = url
    url, doi_reason = trim_doi_url(url)

    if url != before and doi_reason:
        reasons.append(doi_reason)

    # Odstranění teček na úplném konci URL.
    before = url
    url = re.sub(r'\.+$', '', url)

    if url != before:
        reasons.append("odstranena_koncova_tecka")

    # Finální bezpečné ořezání koncové interpunkce.
    before = url
    url = url.rstrip(TRAILING_SAFE_PUNCTUATION)

    if url != before:
        reasons.append("finalni_odstraneni_interpunkce")

    return url, reasons


def suggest_clean_url(url):
    """
    Podezřelé případy.

    Tady URL rovnou neodmítáme, ale dáme ji do url_podezrele.csv
    a případně navrhneme zkrácenou verzi.
    """

    reasons = []
    suggested = ""

    def set_suggestion(candidate, reason):
        nonlocal suggested

        if not candidate or candidate == url:
            return

        if not starts_like_url(candidate):
            return

        if not has_valid_domain(candidate):
            return

        if not suggested or len(candidate) < len(suggested):
            suggested = candidate

        reasons.append(reason)

    # GitHub URL nehodnotíme těmito obecnými podezřelými pravidly,
    # protože GitHub cesty často legitimně obsahují velká písmena,
    # tečky a technické názvy souborů.
    if is_github_domain(url):
        return suggested, reasons

    match = re.search(r'/\.[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]$', url)

    if match:
        candidate = re.sub(r'/\.[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]$', '/', url)
        set_suggestion(
            candidate,
            "podezrely_konec_lomitko_tecka_velke_pismeno"
        )

    ext_pattern = (
        r'html|htm|shtml|php|asp|aspx|jsp|pdf|png|jpg|jpeg|gif|svg|'
        r'zip|rar|gz|tar|txt|csv|json|xml|ps|doc|docx|xls|xlsx|ppt|pptx|git'
    )

    match = re.search(
        rf'(\.(?i:{ext_pattern}))\.[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ0-9]',
        url
    )

    if match:
        candidate = url[:match.end(1)]
        set_suggestion(
            candidate,
            "podezrely_text_za_souborovou_priponou"
        )

    match = re.search(
        r'(.+)\.[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ][a-záčďéěíňóřšťúůýž]+$',
        url
    )

    if match:
        candidate = match.group(1)
        set_suggestion(
            candidate,
            "podezrely_text_za_teckou"
        )

    match = re.search(
        r'(.+)\.[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]{1,3}$',
        url
    )

    if match:
        candidate = match.group(1)
        set_suggestion(
            candidate,
            "podezrela_kratka_pripona_za_teckou"
        )

    match = re.search(
        r'(.+?)(\d+(?:\.\d+)+[A-Za-zÁČĎÉĚÍŇÓŘŠŤÚŮÝŽáčďéěíňóřšťúůýž].*)$',
        url
    )

    if match:
        candidate = match.group(1)
        set_suggestion(
            candidate,
            "podezrele_nalepene_cislovani_kapitoly"
        )

    # Číslo za poslední tečkou samo o sobě není důvod URL zkracovat.
    #
    # Původní obecné pravidlo označovalo každou URL odpovídající tvaru
    # "...<tečka><číslo>" jako podezřelou a navrhovalo odstranění poslední
    # číselné části. To poškozovalo legitimní adresy, zejména DOI, například:
    # - https://doi.org/10.1080/00031305.2016.1209129
    # - http://dx.doi.org/10.1016/j.snb.2014.06.075
    # - http://journals.ametsoc.org/doi/abs/10.1175/MWR3189.1
    # Stejný tvar používají také jiné platné identifikátory, např. arXiv.
    # Proto zde koncovou část ".<číslo>" zachováváme. Specifičtější pravidlo
    # výše pro nalepené číslování kapitoly zůstává aktivní.

    match = re.search(
        r'(.*/)([A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]{5,})$',
        url
    )

    if match:
        candidate = match.group(1)
        set_suggestion(
            candidate,
            "podezrely_posledni_segment_velkymi_pismeny"
        )

    if re.search(r'[ÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]', url) and re.search(
        r'[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]{5,}$',
        url
    ):
        reasons.append(
            "podezrely_cesky_velky_text_na_konci"
        )

    return suggested, reasons


def classify_url(raw_url, clean_input, source_type, filename, page_number):
    clean, clean_reasons = basic_clean_url(clean_input)

    row = {
        "pdf_soubor": filename,
        "strana": page_number,
        "typ": source_type,
        "url_raw": raw_url,
        "url_clean": clean,
        "url_navrzena": "",
        "stav": "",
        "confidence": "",
        "duvod": ""
    }

    if not clean:
        row["stav"] = "ODMITNUTO"
        row["confidence"] = "none"
        row["duvod"] = unique_reasons(
            clean_reasons + ["prazdna_url_po_cisteni"]
        )
        return row

    if not starts_like_url(clean):
        row["stav"] = "ODMITNUTO"
        row["confidence"] = "none"
        row["duvod"] = unique_reasons(
            clean_reasons + ["nezacina_http_nebo_https"]
        )
        return row

    if re.search(r'[ \t\r\n\f\v]', clean):
        row["stav"] = "ODMITNUTO"
        row["confidence"] = "none"
        row["duvod"] = unique_reasons(
            clean_reasons + ["obsahuje_whitespace"]
        )
        return row

    if not has_valid_domain(clean):
        row["stav"] = "ODMITNUTO"
        row["confidence"] = "none"
        row["duvod"] = unique_reasons(
            clean_reasons + ["neplatna_nebo_neuplna_domena"]
        )
        return row

    if source_type == "klikaci_odkaz":
        row["stav"] = "OK"
        row["confidence"] = "high"
        row["duvod"] = unique_reasons(
            clean_reasons + ["skutecny_pdf_hyperlink"]
        )
        return row

    suggested, suspicious_reasons = suggest_clean_url(clean)

    if suspicious_reasons:
        row["stav"] = "PODEZRELE"
        row["confidence"] = (
            "medium_low"
            if source_type == "text_pres_newline"
            else "medium"
        )
        row["url_navrzena"] = suggested
        row["duvod"] = unique_reasons(
            clean_reasons + suspicious_reasons
        )
        return row

    row["stav"] = "OK"

    if source_type == "text_pres_newline":
        row["confidence"] = "medium_low"
        source_reason = "url_z_textu_pres_newline"
    else:
        row["confidence"] = "medium"
        source_reason = "url_z_textu"

    row["duvod"] = unique_reasons(
        clean_reasons + [source_reason]
    )

    return row


def write_row(
    row,
    writer_all,
    writer_ok,
    writer_suspicious,
    writer_rejected,
    seen_all,
    seen_suspicious
):
    all_key = (
        row["pdf_soubor"],
        row["strana"],
        row["typ"],
        row["url_raw"],
        row["url_clean"],
        row["stav"]
    )

    if all_key in seen_all:
        return False

    seen_all.add(all_key)
    writer_all.writerow(row)

    if row["stav"] == "OK":
        writer_ok.writerow(row)

    elif row["stav"] == "PODEZRELE":
        suspicious_key = (
            row["url_raw"],
            row["url_clean"],
            row["url_navrzena"],
            row["duvod"]
        )

        if suspicious_key not in seen_suspicious:
            seen_suspicious.add(suspicious_key)
            writer_suspicious.writerow(row)

    elif row["stav"] == "ODMITNUTO":
        writer_rejected.writerow(row)

    return True


def add_to_counts(row, counts):
    if row["stav"] == "OK":
        counts["ok"] += 1
    elif row["stav"] == "PODEZRELE":
        counts["suspicious"] += 1
    elif row["stav"] == "ODMITNUTO":
        counts["rejected"] += 1


with (
    open(output_all, "w", newline="", encoding="utf-8-sig") as file_all,
    open(output_ok, "w", newline="", encoding="utf-8-sig") as file_ok,
    open(output_suspicious, "w", newline="", encoding="utf-8-sig") as file_suspicious,
    open(output_rejected, "w", newline="", encoding="utf-8-sig") as file_rejected
):

    writer_all = csv.DictWriter(file_all, fieldnames=CSV_COLUMNS)
    writer_ok = csv.DictWriter(file_ok, fieldnames=CSV_COLUMNS)
    writer_suspicious = csv.DictWriter(file_suspicious, fieldnames=CSV_COLUMNS)
    writer_rejected = csv.DictWriter(file_rejected, fieldnames=CSV_COLUMNS)

    writer_all.writeheader()
    writer_ok.writeheader()
    writer_suspicious.writeheader()
    writer_rejected.writeheader()

    pdf_files = [
        f for f in os.listdir(pdf_folder)
        if f.lower().endswith(".pdf")
    ]

    total = len(pdf_files)

    print(f"Nalezeno PDF: {total}")

    seen_all = set()
    seen_suspicious = set()

    counts = {
        "ok": 0,
        "suspicious": 0,
        "rejected": 0
    }

    for i, filename in enumerate(pdf_files, start=1):
        path = os.path.join(pdf_folder, filename)

        print("\n-----------------------------------")
        print(f"[{i}/{total}] {filename}")

        try:
            doc = fitz.open(path)

            for page_number in range(len(doc)):
                page = doc[page_number]
                page_index = page_number + 1

                # 1) Skutečné klikací odkazy z PDF anotací.
                # Tyto odkazy mají nejvyšší důvěru, protože jsou přímo hyperlinky v PDF.
                for link in page.get_links():
                    uri = link.get("uri")

                    if not uri:
                        continue

                    row = classify_url(
                        raw_url=uri,
                        clean_input=uri,
                        source_type="klikaci_odkaz",
                        filename=filename,
                        page_number=page_index
                    )

                    was_written = write_row(
                        row,
                        writer_all,
                        writer_ok,
                        writer_suspicious,
                        writer_rejected,
                        seen_all,
                        seen_suspicious
                    )

                    if was_written:
                        add_to_counts(row, counts)

                # 2) URL nalezené přímo v textu PDF stránky.
                # Tady platí všechna pravidla pro newline, DOI, GitHub atd.
                raw_text = page.get_text("text")
                url_candidates = extract_http_urls_from_text(raw_text)

                for candidate in url_candidates:
                    row = classify_url(
                        raw_url=candidate["url_raw"],
                        clean_input=candidate["url_for_cleaning"],
                        source_type=candidate["source_type"],
                        filename=filename,
                        page_number=page_index
                    )

                    was_written = write_row(
                        row,
                        writer_all,
                        writer_ok,
                        writer_suspicious,
                        writer_rejected,
                        seen_all,
                        seen_suspicious
                    )

                    if was_written:
                        add_to_counts(row, counts)

            doc.close()

            file_all.flush()
            file_ok.flush()
            file_suspicious.flush()
            file_rejected.flush()

        except Exception as e:
            row = {
                "pdf_soubor": filename,
                "strana": "",
                "typ": "chyba_pdf",
                "url_raw": "",
                "url_clean": "",
                "url_navrzena": "",
                "stav": "ODMITNUTO",
                "confidence": "none",
                "duvod": str(e)
            }

            was_written = write_row(
                row,
                writer_all,
                writer_ok,
                writer_suspicious,
                writer_rejected,
                seen_all,
                seen_suspicious
            )

            if was_written:
                add_to_counts(row, counts)

        time.sleep(0.05)

print("\nHotovo.")
print(f"Všechny výskyty: {output_all}")
print(f"Automaticky přijaté URL: {output_ok}")
print(f"Podezřelé URL k ruční kontrole: {output_suspicious}")
print(f"Odmítnuté hodnoty: {output_rejected}")

print("\nSouhrn:")
print(f"OK: {counts['ok']}")
print(f"PODEZRELE: {counts['suspicious']}")
print(f"ODMITNUTO: {counts['rejected']}")
