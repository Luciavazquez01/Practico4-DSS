import pathlib
import re
import pytest
import os

# Ajusta la ruta al archivo que contiene InvoiceService
SRC_PATH = pathlib.Path(os.getenv("INVOICE_SERVICE_PATH", "services/backend/src/services/invoiceService.Ts"))

def read_source(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        pytest.skip(f"Archivo fuente no encontrado: {path}")

def find_andwhereraw_expressions(src: str):
    """
    Extrae las expresiones pasadas a andWhereRaw(...).
    Retorna lista de strings (contenido dentro de los paréntesis).
    """
    pattern = re.compile(r"andWhereRaw\s*\(\s*(?P<expr>.*?)\s*\)", re.DOTALL)
    return [m.group("expr") for m in pattern.finditer(src)]

def looks_vulnerable(expr: str) -> bool:
    """
    Heurística simple para marcar posible SQLi:
    - contiene las variables 'operator' y 'status'
    - y usa concatenación literal ( '+' ) o template literal (${...})
    """
    compact = re.sub(r"\s+", " ", expr)
    has_operator = "operator" in compact
    has_status = "status" in compact
    has_concat_like = bool(re.search(r"\+|\$\{", compact))
    # también detecta patrones de cierre/abrir comillas comunes: "' + operator" o "operator + '"
    has_quote_concat = bool(re.search(r"['\"]\s*\+\s*operator|operator\s*\+\s*['\"]", compact))
    return (has_operator and has_status) and (has_concat_like or has_quote_concat)

def test_invoice_service_no_andwhereraw_concatenation():
    src = read_source(SRC_PATH)
    exprs = find_andwhereraw_expressions(src)

    if not exprs:
        pytest.skip("No se encontraron llamadas a andWhereRaw() en el archivo fuente.")

    vulnerable = []
    for e in exprs:
        if looks_vulnerable(e):
            vulnerable.append(e.strip())

    assert not vulnerable, (
        "Posible SQL Injection detectada: se encontraron llamadas a andWhereRaw(...) "
        "que concatenan variables (operator/status). Ejemplos:\n\n" + "\n\n---\n\n".join(vulnerable)
    )