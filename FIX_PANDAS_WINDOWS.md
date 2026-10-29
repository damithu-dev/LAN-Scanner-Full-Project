# Fixing `ImportError: DLL load failed while importing vectorized` (Windows)

> **TL;DR** — Nothing is wrong with your code or with pandas. Windows code-integrity
> (Smart App Control / WDAC / AppLocker) refused to load one of pandas' compiled
> `.pyd` files. Streamlit imports pandas during *its own* start-up, so
> `streamlit run dashboard/app.py` can never start while that file is blocked.
>
> **Fastest fix (no pandas needed at all):**
>
> ```bat
> python run_dashboard.py --backend standalone
> ```
>
> That opens a full web dashboard (scan controls, progress bar, host/port table,
> charts, CVE hints, JSON/CSV/XML/HTML/Word downloads) that uses **only the Python
> standard library**.
>
> **Want the Streamlit version back?** Run `python diagnose_windows_env.py`, then
> read [Option 2](#option-2--unblock-and-reinstall-the-packages) below.

---

## 1. What the error actually means

```
ImportError: DLL load failed while importing vectorized:
An Application Control policy has blocked this file.
```

The second line is not produced by Python. It comes from **Windows code integrity**
(`ci.dll` / the WDAC engine). One of these is active on the machine:

| Mechanism | Typical owner | Notes |
| --- | --- | --- |
| **Smart App Control (SAC)** | Windows 11, consumer PCs | Blocks unsigned / low-reputation binaries. Cannot be re-enabled once switched off (only a Windows reset restores it). |
| **WDAC** (Windows Defender Application Control) | IT departments, managed PCs | Allow-list based; blocks anything not signed/listed. |
| **AppLocker** | Enterprise / school PCs | Rule based (path, publisher, hash). |
| **Defender Application Control** | Some managed builds | Policy-driven. |

When such a policy is on, Windows refuses to load the file **at the moment Python
tries to import it** — which is why `pip install pandas` succeeds (writing files is
allowed) but `import pandas` fails (loading code is not).

The file being refused in your traceback is this one:

```
.venv\Lib\site-packages\pandas\_libs\tslibs\vectorized.cp312-win_amd64.pyd
                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

(`cp312` = CPython 3.12; `cp311`, `cp313`, etc. appear on other versions.)

## 2. Why the website died immediately

Your traceback chain is the whole story:

```
dashboard\app.py line 16  ->  import pandas as pd
   ... -> pandas/_libs/interval.pyx -> hashtable.pyx -> missing.pyx
   ... -> pandas/_libs/tslibs/__init__.py -> from pandas._libs.tslibs.vectorized import ...
   ImportError: ... blocked this file
```

Two independent reasons the page could not load:

1. `dashboard/app.py` imported pandas at the top. **Fixed in this version** — `app.py`
   no longer imports pandas anywhere; tables are plain lists of dicts and charts are
   plain dicts, which Streamlit renders natively.
2. **Streamlit itself imports pandas at start-up**
   (`streamlit/type_util.py` → `pyarrow` → `pandas`). So even a pandas-free
   `app.py` cannot start under `streamlit run` while pandas is blocked. This is why
   the project now ships a second, dependency-free dashboard.

## 3. Option 1 — Use the dashboard that does not need pandas (works today)

```bat
python run_dashboard.py                       :: auto-detects, picks the best backend
python run_dashboard.py --backend standalone  :: force the stdlib dashboard
```

Then open <http://127.0.0.1:8501>.

`run_dashboard.py` first tests `import pandas, streamlit` **in a separate process**.
If that fails because of a policy block, it prints the explanation and starts the
stdlib dashboard instead — no crash, no traceback page.

What the standalone dashboard supports: the same scan modes (TCP connect / SYN /
UDP / ARP sweep), port selections, thread and timeout sliders, rate limiting,
banner grabbing, CVE hints, sortable/filterable results table, service and risk
charts, and JSON / CSV / XML / HTML / Word report downloads.

## 4. Option 2 — Unblock and reinstall the packages

Run the diagnostics first. It tells you *which* mechanism blocked the file and
copies the exact paths involved:

```bat
python diagnose_windows_env.py
```

It reports: the interpreter and venv in use, an isolated import test for each
dependency, Smart App Control state (registry
`HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy`), deployed WDAC policies
(`CiTool -lp`), AppLocker rules, recent
`Microsoft-Windows-CodeIntegrity/Operational` events, and whether the blocked
`.pyd` carries a "downloaded from the internet" marker (`Zone.Identifier`).

### 4a. Clear the "downloaded file" marker

Files copied from a ZIP/OneDrive/course download are tagged as internet content,
and policies treat them far more harshly:

```powershell
Unblock-File -LiteralPath ".venv\Lib\site-packages\pandas\_libs\tslibs\vectorized.cp312-win_amd64.pyd"
```

or right-click the file → **Properties** → tick **Unblock** → **OK**.

### 4b. Reinstall from official wheels, outside OneDrive

OneDrive-synced folders (`C:\Users\...\OneDrive\Desktop\...`) are a common trigger:
sync can strip metadata and policies often distrust user-writable, synced paths.
A clean environment elsewhere is the most reliable self-service fix:

```bat
python -m venv C:\Tools\lan-scanner-venv
C:\Tools\lan-scanner-venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install --only-binary=:all: --no-cache-dir -r requirements.txt
python -c "import pandas, streamlit; print(pandas.__version__, streamlit.__version__)"
```

Or let the script do it:

```bat
python diagnose_windows_env.py --repair --venv C:\Tools\lan-scanner-venv
```

`--only-binary=:all:` is important: it guarantees pip downloads pre-built wheels
instead of trying to compile, and it avoids mixing half-installed packages.

### 4c. Ask IT / your administrator to allow-list the folder

This is the only fix that works on a locked-down machine — and it is a
configuration change only an administrator can make. Useful wording for the
request:

> Please allow-list `C:\Tools\lan-scanner-venv\*` (Python 3.12 virtual
> environment, course project) in the Code Integrity / WDAC policy, or issue a
> supplemental policy that permits the Python executable and its `.pyd` extension
> modules. Files: `python.exe`, `python312.dll`, `*.pyd` under that folder.

For an administrator (elevated PowerShell), these commands *inspect* the current
policy state — they do not change it:

```powershell
CiTool.exe -lp                        # list deployed WDAC policies
(Get-AppLockerPolicy -Effective).RuleCollections | Format-List
Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational -MaxEvents 20 |
  Format-List TimeCreated, Message
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState
```

`VerifiedAndReputablePolicyState`: `0` = Smart App Control off, `1` = enforced,
`2` = evaluation. Values `1`/`2` explain the block on a home PC.

### 4d. Smart App Control (only on a PC you control)

If the diagnostics show Smart App Control is **On** or in **Evaluation**, and you
own the machine and do not need the protection, it can be turned off via
**Windows Security → App & browser control → Smart App Control → Off**.

> ⚠️ Microsoft documents that once Smart App Control is turned off it cannot be
> turned back on without resetting/reinstalling Windows. Decide deliberately, and
> prefer Option 1 if you are unsure.

## 5. Option 3 — Use the terminal scanner

The command-line tool needs only pure-Python packages (`scapy`, `rich`) and is
unaffected by blocked pandas binaries:

```bat
python main.py --help
python main.py -t 192.168.1.0/24 --ports top100 --format html --output report.html
```

## 6. Why other "fixes" do not work

| Attempt | Why it fails |
| --- | --- |
| `pip install pandas==2.1.4` / downgrade | Every pandas version ships compiled `.pyd` files; the policy blocks whichever one loads. |
| `pip install --force-reinstall pandas` | Same block, same message. |
| Running as Administrator | Code-integrity blocks are policy, not permission, errors. |
| Replacing `import pandas` in `app.py` | Helps your code, but Streamlit imports pandas internally. Use the standalone dashboard. |
| Using `--no-cache-dir`, `--prefer-binary` | Only affects downloads, not loading. |
| Deleting `vectorized*.pyd` | Breaks pandas further; the policy is the root cause. |

## 7. FAQ

**It worked yesterday. What changed?**
Windows update, a new WDAC/AppLocker policy pushed by IT, an OneDrive sync that
re-tagged files, or a Smart App Control reputation update.

**The same message mentions `numpy` or `pyarrow` instead.**
Identical root cause — all three ship compiled extensions. The fixes above apply
unchanged (they are also the packages `diagnose_windows_env.py --repair` installs).

**Does the CVE/banner/export functionality still work without pandas?**
Yes. The `scanner/`, `exporters/`, `utils/` and `ui/` packages never used pandas;
only the Streamlit table/chart rendering did, and that has been rewritten.

**Can I keep both dashboards?**
Yes. `python run_dashboard.py` auto-selects; `--backend streamlit` and
`--backend standalone` force one. Both share the same scan engine
(`dashboard/scan_job.py`), so results are identical.

**How do I know the standalone dashboard is running?**
It prints the URL, and <http://127.0.0.1:8501/healthz> returns `ok`.

## 8. Verify your fix

```bat
:: does the environment import pandas now?
python -c "import pandas, streamlit; print('ok', pandas.__version__)"

:: drill into the remaining failure, if any
python diagnose_windows_env.py

:: always-available dashboard
python run_dashboard.py --backend standalone
```

If step 1 prints `ok 2.x.y` and a Streamlit version, `streamlit run dashboard/app.py`
will also work.
