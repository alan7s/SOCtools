import winreg

# ─── Insira o GUID aqui ───────────────────────────────────────────────────────
GUID = "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
# ─────────────────────────────────────────────────────────────────────────────

FIELDS = [
    ("DisplayName",          "Nome do software"),
    ("Publisher",            "Fabricante"),
    ("DisplayVersion",       "Versão"),
    ("InstallDate",          "Data de instalação"),
    ("InstallLocation",      "Diretório de instalação"),
    ("InstallSource",        "Origem da instalação"),
    ("UninstallString",      "Comando de desinstalação"),
    ("QuietUninstallString", "Desinstalação silenciosa"),
    ("URLInfoAbout",         "URL do produto"),
    ("HelpLink",             "Link de suporte"),
    ("Comments",             "Comentários"),
    ("EstimatedSize",        "Tamanho estimado (KB)"),
    ("Language",             "Idioma (LCID)"),
    ("NoModify",             "Permite modificação"),
    ("NoRepair",             "Permite reparo"),
]

registry_paths = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",            "HKLM", "x64"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM", "x86"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",            "HKCU", "x64"),
]

found = False

print("\n" + "═" * 60)
print(f"  GUID: {GUID}")
print("═" * 60)

for hive, base_path, hive_label, arch_label in registry_paths:
    key_path = base_path + "\\" + GUID
    try:
        key = winreg.OpenKey(hive, key_path)
    except FileNotFoundError:
        continue

    found = True
    print(f"\n  Origem  : {hive_label}\\{base_path} [{arch_label}]")
    print(f"  Caminho : {hive_label}\\{key_path}")
    print("  " + "─" * 58)

    for reg_name, label in FIELDS:
        try:
            value, _ = winreg.QueryValueEx(key, reg_name)
            if reg_name == "EstimatedSize":
                value = f"{value:,} KB  (~{value / 1024:.1f} MB)"
            elif reg_name in ("NoModify", "NoRepair"):
                value = "Sim" if value == 1 else "Não"
            print(f"  {label:<28}: {value}")
        except FileNotFoundError:
            pass

    winreg.CloseKey(key)

if not found:
    print("\n  [!] GUID não encontrado em nenhuma chave de desinstalação.")
    print("  Possíveis causas:")
    print("  - Software já desinstalado (chave removida)")
    print("  - GUID pertence apenas ao Windows Installer MSI cache")
    print("  - Entrada presente somente no perfil de outro usuário")

print("\n" + "═" * 60 + "\n")
